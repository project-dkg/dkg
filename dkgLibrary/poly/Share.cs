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

// This file implements Shamir secret sharing and polynomial commitments.
// Shamir's scheme allows you to split a secret value into multiple parts, so called
// shares, by evaluating a secret sharing polynomial at certain indices. The
// shared secret can only be reconstructed (via Lagrange interpolation) if a
// threshold of the participants provide their shares. A polynomial commitment
// scheme allows a committer to commit to a secret sharing polynomial so that
// a verifier can check the claimed evaluations of the committed polynomial.

using SHA256 = System.Security.Cryptography.SHA256;

using System.Runtime.CompilerServices;
using dkg.group;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Crypto;

[assembly: InternalsVisibleTo("dkgLibraryTests")]

namespace dkg.poly
{
    public class Share(int I) : IMarshalling, IEquatable<Share>
    {
        internal int I { get; set; } = I;

        public bool Equals(Share? other)
        {
            if (other == null) return false;
            return I == other.I;
        }

        public void MarshalBinary(Stream s)
        {
            BinaryWriter w = new(s);
            w.Write(I);
        }

        public int MarshalSize()
        {
            return sizeof(int);
        }

        public void UnmarshalBinary(Stream s)
        {
            BinaryReader reader = new(s);
            I = reader.ReadInt32();
        }

        public override bool Equals(object? obj)
        {
            return Equals(obj as Share);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return I * 31;
            }
        }
    }

    public class ShareComparer : IComparer<Share>
    {
        public int Compare(Share? x, Share? y)
        {
            ArgumentNullException.ThrowIfNull(x);
            ArgumentNullException.ThrowIfNull(y);
            return x!.I.CompareTo(y!.I);
        }
    }

    // PriShare represents a private share.
    public class PriShare(int I, IScalar V) : Share(I), IMarshalling, IEquatable<PriShare>
    {
        public IScalar V { get; set; } = V;

        public bool Equals(PriShare? other)
        {
            if (other == null) return false;

            if (ReferenceEquals(this, other))
                return true;

            return V.Equals(other.V) && base.Equals(other);
        }

        // Returns the hash representation of this share
        public byte[] Hash()
        {
            var h = SHA256.HashData(V.GetBytes());
            var iBytes = BitConverter.GetBytes(I);
            h = [.. h, .. iBytes];
            return h;
        }

        public new void MarshalBinary(Stream s)
        {
            base.MarshalBinary(s);
            V.MarshalBinary(s);
        }

        public new int MarshalSize()
        {
            return base.MarshalSize() + V.MarshalSize();
        }

        public override string ToString()
        {
            return $"{{PriShare: I = {I}; V = {V}}}";
        }

        public new void UnmarshalBinary(Stream s)
        {
            base.UnmarshalBinary(s);
            V.UnmarshalBinary(s);
        }

        public override bool Equals(object? obj)
        {
            return Equals(obj as PriShare);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return base.GetHashCode() + 23 * V.GetHashCode();
            }
        }
    }

    // PubShare represents a public share.
    public class PubShare(int I, IPoint V) : Share(I), IEquatable<PubShare>
    {
        internal IPoint V { get; set; } = V;
        public bool Equals(PubShare? other)
        {
            if (other == null) return false;

            if (ReferenceEquals(this, other))
                return true;

            return V.Equals(other.V) && base.Equals(other);
        }

        // Hash returns the hash representation of this share.
        public byte[] Hash()
        {
            var h = SHA256.HashData(V.GetBytes());
            var iBytes = BitConverter.GetBytes(I);
            h = [.. h, .. iBytes];
            return h;
        }
        public new void MarshalBinary(Stream s)
        {
            base.MarshalBinary(s);
            V.MarshalBinary(s);
        }

        public new int MarshalSize()
        {
            return base.MarshalSize() + V.MarshalSize();
        }
        public override string ToString()
        {
            return $"{{PubShare: I = {I}; V = {V}}}";
        }
        public new void UnmarshalBinary(Stream s)
        {
            base.UnmarshalBinary(s);
            V.UnmarshalBinary(s);
        }

        public override bool Equals(object? obj)
        {
            return Equals(obj as PubShare);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return base.GetHashCode() + 23 * V.GetHashCode();
            }
        }
    }
}
