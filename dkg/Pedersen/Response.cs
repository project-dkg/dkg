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

namespace dkg
{
    public enum ResponseStatus
    {
        // StatusComplaint is a constant value meaning that a verifier issues
        // a Complaint against its Dealer.
        Complaint = 0,
        // StatusApproval is a constant value meaning that a verifier agrees with
        // the share it received.
        Approval = 1
    }


    // Response is sent by the verifiers to all participants and holds each
    // individual validation or refusal of a Deal.
    public class Response
    {
        // SessionId related to this run of the protocol
        public byte[] SessionId { get; set; }

        // Index of the verifier issuing this Response from the new set of nodes
        public int Index { get; set; }

        // Complain/Approval
        public ResponseStatus Status { get; set; }

        // Signature over the whole packet
        public byte[] Signature { get; set; }
        public Response(byte[] sessionId, int index)
        {
            SessionId = sessionId;
            Index = index;
            Signature = [];
            Status = ResponseStatus.Complaint;
        }

        public byte[] Hash()
        {
            MemoryStream b = new();
            BinaryWriter w = new(b);
            w.Write(SessionId);
            w.Write(Index);
            w.Write(Status == ResponseStatus.Approval ? true:false);
            w.Write(Signature);
            return Suite.Hash.ComputeHash(b.ToArray());
        }
    }

}
