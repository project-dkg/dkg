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

using dkg.group;
using dkg.poly;
using System;
using System.Linq.Expressions;

namespace dkg.vss
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

        private static readonly Exception ErrDealAlreadyProcessed = new Exception();

        // VerifyDeal analyzes the deal and returns an error if it's incorrect. If 
        // inclusion is true, it also returns an error if it is the second time this struct 
        // analyzes a Deal
        public ComplaintCode VerifyDeal(Deal d, bool inclusion)
        {
            if (Deal != null && inclusion)
                return ComplaintCode.AlreadyProcessed;

            if (Deal == null)
            {
                Commitments = d.Commitments;
                SessionId = d.SessionId;
                Deal = d;
                T = d.T;
            }

            if (!VssTools.ValidT(d.T, Verifiers))
                return ComplaintCode.InvalidThreshold;

            if (d.T != T)
                return ComplaintCode.IncompatibeThreshold;

            if (!SessionId.SequenceEqual(d.SessionId))
                return ComplaintCode.SessionIdDoesNotMatch;

            var fi = d.SecShare;
            if (fi.I < 0 || fi.I >= Verifiers.Length)
                return ComplaintCode.IndexOutOfBound;

            // Compute fi * G
            var fig = Suite.G.Point().Base().Mul(fi.V);
            var commitPoly = new PubPoly(Suite.G, Suite.G.Point().Base(), d.Commitments);

            var pubShare = commitPoly.Eval(fi.I);
            if (!fig.Equals(pubShare.V))
                return ComplaintCode.ShareDoesNotVerify;

            return ComplaintCode.NoComplaint;
        }

        // ProcessResponse verifies the validity of the given response and stores it
        // internall. It is  the public version of verifyResponse created this way to
        // allow higher-level package to use these functionalities.

        public string? ProcessResponse(Response r)
        {
            return VerifyResponse(r);
        }

        public string? VerifyResponse(Response r)
        {
            if (SessionId != null && !SessionId.SequenceEqual(r.SessionId))
                return "VerifyResponse: receiving inconsistent sessionID in response";

            var pub = VssTools.GetPub(Verifiers, r.Index);
            if (pub == null)
                return "VerifyResponse: index out of bounds in response";

            try
            {
                Schnorr.Verify(Suite.G, Suite.Hash, pub, r.Hash(), r.Signature);
            }
            catch (DkgError ex)
            {
                return $"{ex.Source}: ${ex.Message}";
            }

            return AddResponse(r);
        }

        public string? VerifyJustification(Justification j)
        {
            if (VssTools.GetPub(Verifiers, j.Index) == null)
                return "VerifyJustification: index out of bounds in justification";

            if (!Responses.TryGetValue(j.Index, out Response? r))
                return "VerifyJustification: no complaints received for this justification";

            if (r.Status != ResponseStatus.Complaint)
                return "VerifyJustification: justification received for an approval";

            var Complaint = VerifyDeal(j.Deal, false);
            if (Complaint != ComplaintCode.NoComplaint)
            {
                // if one justification is bad, then flag the dealer as malicious
                BadDealer = true;
                return Response.GetComplaintMessage(Complaint);
            }
            r.Status = ResponseStatus.Approval;
            return null;
        }
        public string? AddResponse(Response r)
        {
            if (VssTools.GetPub(Verifiers, r.Index) == null)
                return "AddResponse: index out of bounds";

            if (Responses.ContainsKey(r.Index))
                return "AddResponse: response from same origin already exists";

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
        // MissingResponses returns the indexes of the expected but missing responses.
        public int[] MissingResponses()
        {
            List<int> absents = [];
            for (int i = 0; i < Verifiers.Length; i++)
            {
                if (!Responses.ContainsKey(i))
                {
                    absents.Add(i);
                }
            }
            return [.. absents];
        }
    }
}
