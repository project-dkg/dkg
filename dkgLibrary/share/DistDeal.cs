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
    // Deal holds the Deal for one participant as well as the index of the issuing
    // Dealer.
    public class DistDeal : IMarshalling, IEquatable<DistDeal>
    {
        // Index of the Dealer in the list of participants
        public int Index { get; set; }

        // Deal issued for another participant
        public EncryptedDeal EncDeal { get; set; }

        // Signature over the whole message
        public byte[] Signature { get; set; } = [];

        public DistDeal()
        {
            Index = 0;
            EncDeal = new EncryptedDeal();
        }
        public DistDeal(int index, EncryptedDeal encryptedDeal)
        {
            Index = index;
            EncDeal = encryptedDeal;
        }
        public bool Equals(DistDeal? other)
        {
            if (other == null)
                return false;

            if (ReferenceEquals(this, other))
                return true;

            // For valid case it would be enough to check signature but we overperform here
            return Signature.SequenceEqual(other.Signature) &&
                   Index == other.Index &&
                   EncDeal.Equals(other.EncDeal);
        }

        public override bool Equals(object? obj)
        {
            return Equals(obj as DistDeal);
        }
        public override int GetHashCode()
        {
            return HashCode.Combine(Signature, Index, EncDeal);
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

        public byte[] GetBytesForSignature()
        {
            MemoryStream s = new();
            BinaryWriter bw = new(s);
            bw.Write(Index);
            EncDeal.MarshalBinary(s);
            return s.ToArray();
        }
        public void MarshalBinary(Stream s)
        {
            BinaryWriter bw = new(s);
            bw.Write(Index);
            EncDeal.MarshalBinary(s);
            bw.Write(Signature.Length);
            s.Write(Signature, 0, Signature.Length);
        }

        public int MarshalSize()
        {
            return 2 * sizeof(int) + Signature.Length + EncDeal.MarshalSize();
        }

        public void UnmarshalBinary(Stream s)
        {
            BinaryReader br = new(s);
            Index = br.ReadInt32();
            EncDeal.UnmarshalBinary(s);
            int l = br.ReadInt32();
            Signature = new byte[l];
            s.Read(Signature, 0, Signature.Length);
        }
    }
}
