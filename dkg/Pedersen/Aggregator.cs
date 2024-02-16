// Copyright (C) 2024 Maxim [maxirmx] Samsonov (www.sw.consulting)
// All rights reserved.
// This file is a part of dkg applcation
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS
// BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.


using System.Net.NetworkInformation;

namespace dkg
{
    // Aggregator is used to collect all deals, and responses for one protocol run.
    // It brings common functionalities for both Dealer and Verifier structs.
    public class Aggregator
    {
        public IPoint DealerPublicKey { get; set; }
        public IPoint[] Verifiers { get; set; }
        public IPoint[] Commitments { get; set; }
        public Dictionary<int, Response> Responses { get; set; }
        public byte[] SessionId { get; set; }
        public Deal? Deal { get; set; }
        public int T { get; set; }
        public bool BadDealer { get; set; }
        public bool Timeout { get; set; }

        // New Aggregator returns a structure capable of storing Responses about a
        // deal and check if the deal is certified or not.
        public Aggregator(IPoint dealer, IPoint[] verifiers, IPoint[] commitments, int t, byte[] sid)
        {
            DealerPublicKey = dealer;
            Verifiers = verifiers;
            Commitments = commitments;
            T = t;
            SessionId = sid;
            Responses = [];
        }

        public Aggregator(IPoint[] verifiers)
        {
            SessionId = [];
            Responses = [];
            Commitments = [];
            SessionId = [];
            Verifiers = verifiers;
            DealerPublicKey = Suite.G.Point();
        }

        private static readonly Exception ErrDealAlreadyProcessed = new Exception("vss: verifier already received a deal");

        // VerifyDeal analyzes the deal and returns an error if it's incorrect. If 
        // inclusion is true, it also returns an error if it is the second time this struct 
        // analyzes a Deal
        public Exception? VerifyDeal(Deal d, bool inclusion)
        {
            if (Deal != null && inclusion)
            {
                return ErrDealAlreadyProcessed;
            }

            if (Deal == null)
            {
                Commitments = d.Commitments;
                SessionId = d.SessionId;
                Deal = d;
                T = d.T;
            }

            if (!Tools.ValidT(d.T, Verifiers))
            {
                return new Exception("vss: invalid t received in Deal");
            }

            if (d.T != T)
            {
                return new Exception("vss: incompatible threshold - potential attack");
            }

            if (!SessionId.SequenceEqual(d.SessionId))
            {
                return new Exception("vss: find different sessionIDs from Deal");
            }

            var fi = d.SecShare;
            if (fi.I < 0 || fi.I >= Verifiers.Length)
            {
                return new Exception("vss: index out of bounds in Deal");
            }

            // Compute fi * G
            var fig = Suite.G.Point().Base().Mul(fi.V);

            var commitPoly = new PubPoly(Suite.G, Suite.G.Point().Base(), d.Commitments);

            var pubShare = commitPoly.Eval(fi.I);
            if (!fig.Equals(pubShare.V))
            {
                return new Exception("vss: share does not verify against commitments in Deal");
            }

            return null;
        }

        public Exception? AddResponse(Response r)
        {
            if (Tools.FindPub(Verifiers, r.Index) ==  null)
            {
                return new Exception("vss: index out of bounds in Complaint");
            }

            if (Responses.ContainsKey(r.Index))
            {
                return new Exception("vss: already existing response from same origin");
            }

            Responses[r.Index] = r;
            return null;
        }

        // DealCertified returns true if the deal is certified.
        // For a deal to be certified, it needs to comply to the following
        // conditions in two different cases, since we are not working with the
        // synchrony assumptions from Feldman's VSS:
        // Before the timeout (i.e. before the "period" ends):
        // 1. there is at least t approvals
        // 2. all complaints must be justified (a complaint becomes an approval when
        // justified) -> no complaints
        // 3. there must not be absent responses
        // After the timeout, when the "period" ended, we replace the third condition:
        // 3. there must not be more than n-t missing responses (otherwise it is not
        // possible to retrieve the secret).
        // If the caller previously called `SetTimeout` and `DealCertified()` returns
        // false, the protocol MUST abort as the deal is not and never will be validated.
        public bool DealCertified()
        {
            var absentVerifiers = 0;
            var approvals = 0;
            var isComplaint = false;

            for (var i = 0; i < Verifiers.Length; i++)
            {
                if (!Responses.TryGetValue(i, out var r))
                {
                    absentVerifiers++;
                }
                else if (r.Status == ResponseStatus.Complaint)
                {
                    isComplaint = true;
                }
                else if (r.Status == ResponseStatus.Approval)
                {
                    approvals++;
                }
            }

            var enoughApprovals = approvals >= T;
            var tooMuchAbsents = absentVerifiers > Verifiers.Length - T;
            var baseCondition = !BadDealer && enoughApprovals && !isComplaint;

            if (Timeout)
            {
                return baseCondition && !tooMuchAbsents;
            }

            return baseCondition && !(absentVerifiers > 0);
        }

    }
}
