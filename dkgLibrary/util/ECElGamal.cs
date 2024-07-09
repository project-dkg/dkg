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
    /*
    This class illustrates how the crypto toolkit may be used
    to perform "pure" ElGamal encryption,
    in which the message to be encrypted is small enough to be embedded
    directly within a group element (e.g., in an elliptic curve point).
    For basic background on ElGamal encryption see for example
    http://en.wikipedia.org/wiki/ElGamal_encryption.

    Most public-key crypto libraries tend not to support embedding data in points,
    in part because for "vanilla" public-key encryption you don't need it:
    one would normally just generate an ephemeral Diffie-Hellman secret
    and use that to seed a symmetric-key crypto algorithm such as AES,
    which is much more efficient per bit and works for arbitrary-length messages.
    However, in many advanced public-key crypto algorithms it is often useful
    to be able to embedded data directly into points and compute with them:
    as just one of many examples,
    the proactively verifiable anonymous messaging scheme prototyped in Verdict
    (see http://dedis.cs.yale.edu/dissent/papers/verdict-abs).
    */

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

        public static byte[] DecryptData(IScalar privateKey, (IPoint C1, IPoint C2) cipher)
        {
            Secp256k1Point? M = cipher.C2.Sub(cipher.C1.Mul(privateKey)) as Secp256k1Point ?? throw new InvalidCastException("Decryption failed: cypher type does not match");
            byte[] plainBytes = M.ExtractData();
            return plainBytes;
        }

        public static (IPoint C1, IPoint C2) Encrypt(IGroup G, IPoint publicKey, string plaintext)
        {
            return Encrypt(G, publicKey, Encoding.UTF8.GetBytes(plaintext));
        }

        public static string DecryptString(IScalar privateKey, (IPoint C1, IPoint C2) ciphertext)
        {
            byte[] plaintextBytes = DecryptData(privateKey, ciphertext);
            return Encoding.UTF8.GetString(plaintextBytes);
        }
    }
}
