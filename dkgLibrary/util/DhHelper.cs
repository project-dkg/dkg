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
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Text;

namespace dkg.util
{
    public static class DhHelper
    {
        public const int sharedKeySize = 32;
        public const int nonceSizeInBytes = 12;
        public const int tagSizeInBytes = 16;

        // dhExchange computes the shared key from a private key and a public key
        public static IPoint DhExchange(IScalar ownPrivate, IPoint remotePublic)
        {
            return remotePublic.Mul(ownPrivate);
        }

        // CreateAEAD returns the AEAD cipher to be used to encrypt a share
        public static AesGcm CreateAEAD(IPoint preSharedKey, byte[] hkdfContext)
        {
            var sharedKey = CreateHKDF(preSharedKey.GetBytes(), hkdfContext);
            var aes = Aes.Create();
            aes.Key = sharedKey;
            return new AesGcm(aes.Key, tagSizeInBytes);
        }

        public static byte[] CreateHKDF(byte[] preSharedKey, byte[] hkdfContext)
        {
            // Create HKDF generator
            HkdfBytesGenerator hkdf = new(new Sha256Digest());

            // Initialize generator
            hkdf.Init(new HkdfParameters(preSharedKey, hkdfContext, null));

            // Generate shared key
            byte[] sharedKey = new byte[sharedKeySize];
            hkdf.GenerateBytes(sharedKey, 0, sharedKeySize);

            return sharedKey;
        }

        // Context returns the context slice to be used when encrypting a share
        public static byte[] Context(IPoint publicKey, IPoint[] verifiers)
        {
            MemoryStream strm = new();
            strm.Write(Encoding.UTF8.GetBytes("dkg-dealer"));
            publicKey.MarshalBinary(strm);
            strm.Write(Encoding.UTF8.GetBytes("dkg-verifiers"));
            foreach (var vrf in verifiers)
            {
                vrf.MarshalBinary(strm);
            }
            return SHA256.HashData(strm.ToArray());
        }
    }
}
