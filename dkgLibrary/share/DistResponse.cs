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
using dkg.vss;

namespace dkg.share
{
    // Response holds the Response from another participant as well as the index of
    // the target Dealer.
    public class DistResponse : IMarshalling, IEquatable<DistResponse>
    {
        // Index of the Dealer for which this response is for
        public int Index { get; set; }

        // Response issued from another participant
        public Response VssResponse { get; set; }

        public DistResponse()
        {
            Index = -1;
            VssResponse = new();
        }
        public DistResponse(int index, Response vssResponse)
        {
            Index = index;
            VssResponse = vssResponse;
        }
        public bool Equals(DistResponse? other)
        {
            if (other == null)
                return false;

            return Index == other.Index && VssResponse.Equals(other.VssResponse);
        }
        public override bool Equals(object? obj)
        {
            return Equals(obj as DistResponse);
        }
        public override int GetHashCode()
        {
            return HashCode.Combine(Index, VssResponse);
        }
        public void MarshalBinary(Stream s)
        {
            BinaryWriter bw = new(s);
            bw.Write(Index);
            VssResponse.MarshalBinary(s);
        }

        public int MarshalSize()
        {
            return sizeof(int) + VssResponse.MarshalSize();
        }

        public void UnmarshalBinary(Stream s)
        {
            BinaryReader br = new(s);
            Index = br.ReadInt32();
            VssResponse.UnmarshalBinary(s);
        }
        public byte[] GetBytes()
        {
            MemoryStream stream = new();
            MarshalBinary(stream);
            return stream.ToArray();
        }

        public void SetBytes(byte[] bytes)
        {
            MemoryStream stream = new(bytes);
            UnmarshalBinary(stream);
        }

    }
}
