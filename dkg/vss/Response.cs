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

namespace dkg.vss
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

    public enum ComplaintCode
    {
        NoComplaint = 0,
        AlreadyProcessed = 1,
        InvalidThreshold = 2,
        IncompatibeThreshold = 3,
        SessionIdDoesNotMatch = 4,
        IndexOutOfBound = 5,
        ShareDoesNotVerify = 6
    }

    // Response is sent by the verifiers to all participants and holds each
    // individual validation or refusal of a Deal.
    public class Response : IMarshalling, IEquatable<Response>
    {
        static private Dictionary<ComplaintCode, string> complaintCodeToMessage = new Dictionary<ComplaintCode, string>()
        {
            { ComplaintCode.NoComplaint, "No complaint" },
            { ComplaintCode.AlreadyProcessed, "Verifier already processed the deal" },
            { ComplaintCode.InvalidThreshold, "Invalid threshold received" },
            { ComplaintCode.IncompatibeThreshold, "Incompatible threshold - potential attack" },
            { ComplaintCode.SessionIdDoesNotMatch, "SessionIds do not match" },
            { ComplaintCode.IndexOutOfBound, "Index out of bounds" },
            { ComplaintCode.ShareDoesNotVerify, "Share does not verify against commitments" }
        };

        static public string GetComplaintMessage(ComplaintCode code)
        {
            if (complaintCodeToMessage.TryGetValue(code, out string? complaintMessage))
            {
                return complaintMessage;
            }
            else
            {
                return "Unknown complaint code";
            }
        }

        public Response()
        {
            SessionId = [];
            Index = -1;

        }
        public Response(byte[] sessionId, int index)
        {
            SessionId = sessionId;
            Index = index;
        }

        // SessionId related to this run of the protocol
        public byte[] SessionId { get; set; }

        // Index of the verifier issuing this Response from the new set of nodes
        public int Index { get; set; }

        // Complain/Approval
        public ResponseStatus Status { get; set; } = ResponseStatus.Complaint;
        public ComplaintCode Complaint { get; set; } = ComplaintCode.NoComplaint;

        // Signature over the whole packet
        public byte[] Signature { get; set; } = [];

        public byte[] GetBytesForSignature()
        {
            MemoryStream b = new();
            BinaryWriter w = new(b);
            w.Write("response");
            w.Write(SessionId);
            w.Write(Index);
            w.Write(Status == ResponseStatus.Approval);
            return b.ToArray();
        }

        public void MarshalBinary(Stream s)
        {
            BinaryWriter writer = new(s);
            writer.Write(SessionId.Length);
            writer.Write(SessionId);
            writer.Write(Index);
            writer.Write((int)Status);
            writer.Write((int)Complaint);
            writer.Write(Signature.Length);
            writer.Write(Signature);
        }

        public int MarshalSize()
        {
            return sizeof(int) * 5 + SessionId.Length + Signature.Length;
        }

        public void UnmarshalBinary(Stream s)
        {
            BinaryReader reader = new(s);
            int l = reader.ReadInt32();
            SessionId = new byte[l];
            SessionId = reader.ReadBytes(SessionId.Length);
            Index = reader.ReadInt32();
            Status = (ResponseStatus)reader.ReadInt32();
            Complaint = (ComplaintCode)reader.ReadInt32();
            l = reader.ReadInt32();
            Signature = new byte[l];
            Signature = reader.ReadBytes(Signature.Length);
        }

        public byte[] GetBytes()
        {
            MemoryStream ms = new MemoryStream();
            MarshalBinary(ms);
            return ms.ToArray();
        }

        public void SetBytes(byte[] data)
        {
            MemoryStream ms = new(data);
            UnmarshalBinary(ms);
        }

        public bool Equals(Response? other)
        {
            if (other == null)
                return false;

            return SessionId.SequenceEqual(other.SessionId) &&
                   Index == other.Index &&
                   Status == other.Status &&
                   Complaint == other.Complaint &&
                   Signature.SequenceEqual(other.Signature);
        }

        public override bool Equals(object? obj)
        {
            return Equals(obj as Response);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(SessionId, Index, Status, Complaint, Signature);
        }
    }
}


