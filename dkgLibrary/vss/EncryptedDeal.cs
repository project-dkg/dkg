
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
    // EncryptedDeal contains the deal in a encrypted form only decipherable by the
    // correct recipient. The encryption is performed in a similar manner as what is
    // done in TLS. The dealer generates a temporary key pair, signs it with its
    // longterm secret key.
    public class EncryptedDeal :IMarshalling, IEquatable<EncryptedDeal>
    {
        // Ephemeral Diffie Hellman key
        internal byte[] DHKey { get; set; }
        // Signature of the DH key by the longterm key of the dealer
        internal byte[] Signature { get; set; }
        // Nonce used for the encryption
        internal byte[] Nonce { get; set; }
        // AEAD encryption of the marshalled deal 
        internal byte[] Cipher { get; set; }
        internal byte[] Tag { get; set; }

        public EncryptedDeal()
        {
            DHKey = [];
            Signature = [];
            Nonce = [];
            Cipher = [];
            Tag = [];
        }

        public EncryptedDeal(byte[] dhKey, byte[] signatire, byte[] nounce, byte[] cipher, byte[] tag)
        {
            DHKey = dhKey;
            Signature = signatire;
            Nonce = nounce;
            Cipher = cipher;
            Tag = tag;
        }

        public bool Equals(EncryptedDeal? other)
        {
            if (other == null)
                return false;

            if (ReferenceEquals(this, other))
                return true;

            return DHKey.SequenceEqual(other.DHKey) &&
                   Signature.SequenceEqual(other.Signature) &&
                   Nonce.SequenceEqual(other.Nonce) &&
                   Cipher.SequenceEqual(other.Cipher) &&
                   Tag.SequenceEqual(other.Tag);
        }
        public override bool Equals(object? obj)
        {
            return Equals(obj as EncryptedDeal);
        }
        public override int GetHashCode()
        {
            return HashCode.Combine(DHKey, Signature, Nonce, Cipher, Tag);
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

        public void MarshalBinary(Stream s)
        {
            BinaryWriter bw = new(s);
            bw.Write(DHKey.Length);
            bw.Write(DHKey);
            bw.Write(Signature.Length);
            bw.Write(Signature);
            bw.Write(Nonce.Length);
            bw.Write(Nonce);
            bw.Write(Cipher.Length);
            bw.Write(Cipher);
            bw.Write(Tag.Length);
            bw.Write(Tag);
        }

        public int MarshalSize()
        {
            return 5 * sizeof(int) +
                   DHKey.Length + Signature.Length + Nonce.Length + Cipher.Length + Tag.Length;
        }

        public void UnmarshalBinary(Stream s)
        {
            BinaryReader br = new(s);

            int dhKeyLength = br.ReadInt32();
            DHKey = br.ReadBytes(dhKeyLength);

            int signatureLength = br.ReadInt32();
            Signature = br.ReadBytes(signatureLength);

            int nonceLength = br.ReadInt32();
            Nonce = br.ReadBytes(nonceLength);

            int cipherLength = br.ReadInt32();
            Cipher = br.ReadBytes(cipherLength);

            int tagLength = br.ReadInt32();
            Tag = br.ReadBytes(tagLength);
        }
    }
}
