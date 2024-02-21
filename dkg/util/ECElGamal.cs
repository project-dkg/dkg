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
using System.Text;

namespace dkg.util
{
    public static class ECElGamalEncryption
    {
        public static (IPoint C1, IPoint C2) Encrypt(IGroup G, IPoint publicKey, byte[] plaindata)
        {
            IScalar k = G.Scalar();
            IPoint message = G.EmbedData(plaindata);
            IPoint C1 = G.Base().Mul(k);
            IPoint C2 = publicKey.Mul(k).Add(message);
            return (C1, C2);
        }

        public static byte[] DecryptData(IGroup G, IScalar privateKey, (IPoint C1, IPoint C2) cipher)
        {
            Secp256k1Point? M = cipher.C2.Sub(cipher.C1.Mul(privateKey)) as Secp256k1Point;
            if (M == null)
            {
                throw new InvalidCastException("Decryption failed: cypher type does not match");
            }
            byte[] plainBytes = M.ExtractData();
            return plainBytes;
        }

        public static (IPoint C1, IPoint C2) Encrypt(IGroup G, IPoint publicKey, string plaintext)
        {
            return Encrypt(G, publicKey, Encoding.UTF8.GetBytes(plaintext));
        }

        public static string DecryptString(IGroup G, IScalar privateKey, (IPoint C1, IPoint C2) ciphertext)
        {
            byte[] plaintextBytes = DecryptData(G, privateKey, ciphertext);
            return Encoding.UTF8.GetString(plaintextBytes);
        }
    }
}
