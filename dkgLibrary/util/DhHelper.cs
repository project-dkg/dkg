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
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System.Text;

namespace dkg.util
{
    public static class DhHelper
    {
        public const int SharedKeySize = 32;
        public const int NonceSizeInBytes = 12;
        public const int TagSizeInBytes = 16;

        // dhExchange computes the shared key from a private key and a public key
        public static IPoint DhExchange(IScalar ownPrivate, IPoint remotePublic)
        {
            return remotePublic.Mul(ownPrivate);
        }

        // CreateAEAD returns the AEAD cipher to be used to encrypt a share
        public static GcmBlockCipher CreateAEAD(bool mode, IPoint preSharedKey, byte[] hkdfContext, byte[] nonce)
        {
            var sharedKey = CreateHKDF(preSharedKey.GetBytes(), hkdfContext);
            var cipher = new GcmBlockCipher(new AesEngine());
            cipher.Init(mode, new AeadParameters(new KeyParameter(sharedKey), TagSizeInBytes * 8, nonce));
            return cipher;
        }

        public static byte[] CreateHKDF(byte[] preSharedKey, byte[] hkdfContext)
        {
            // Create HKDF generator
            HkdfBytesGenerator hkdf = new(new Sha256Digest());

            // Initialize generator
            hkdf.Init(new HkdfParameters(preSharedKey, hkdfContext, null));

            // Generate shared key
            byte[] sharedKey = new byte[SharedKeySize];
            hkdf.GenerateBytes(sharedKey, 0, SharedKeySize);

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
            // Use BouncyCastle's SHA256 implementation
            var digest = new Sha256Digest();
            var result = new byte[digest.GetDigestSize()];
            var data = strm.ToArray();
            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(result, 0);
            return result;
        }
        public static void Encrypt(GcmBlockCipher cipher, byte[] plaintext, out byte[] encrypted, out byte[] tag)
        {
            // Allocate space for the ciphertext, which may be slightly larger than the plaintext
            encrypted = new byte[cipher.GetOutputSize(plaintext.Length)];

            // Process the plaintext bytes through the cipher
            int len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, encrypted, 0);
            len += cipher.DoFinal(encrypted, len);


            tag = new byte[TagSizeInBytes];

            // Extract the tag from the end of the encrypted array
            Array.Copy(encrypted, len - TagSizeInBytes, tag, 0, TagSizeInBytes);

            // Resize the encrypted array to exclude the tag
            byte[] tempEncrypted = new byte[len - TagSizeInBytes];
            Array.Copy(encrypted, 0, tempEncrypted, 0, len - TagSizeInBytes);
            encrypted = tempEncrypted;
        }

        public static void Decrypt(GcmBlockCipher cipher, byte[] encrypted, byte[] tag, out byte[] decrypted)
        {
            // Combine the encrypted data and tag to conform with how GCMBlockCipher expects its input
            byte[] encryptedWithTag = new byte[encrypted.Length + tag.Length];
            Array.Copy(encrypted, 0, encryptedWithTag, 0, encrypted.Length);
            Array.Copy(tag, 0, encryptedWithTag, encrypted.Length, tag.Length);

            // Allocate space for decryption
            decrypted = new byte[cipher.GetOutputSize(encryptedWithTag.Length)];


            // Decrypt the data
            int len = cipher.ProcessBytes(encryptedWithTag, 0, encryptedWithTag.Length, decrypted, 0);
            cipher.DoFinal(decrypted, len);
        }
    }
}

