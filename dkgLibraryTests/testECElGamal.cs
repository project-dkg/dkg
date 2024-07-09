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

using System.Text;

namespace ECElGamalTests
{
    internal class ECElGamalEncryptionTests
    {
        private IScalar _privateKey;
        private IPoint _publicKey;
        private Secp256k1Group _g;

        [SetUp]
        public void Setup()
        {
            _g = new Secp256k1Group();
            // Generate a random private key and calculate the corresponding public key
            _privateKey = _g.Scalar();
            _publicKey = _g.Base().Mul(_privateKey);
        }

        [Test]
        public void TestEncryptDecrypt()
        {
            string plaintext = "Hello, world!";
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

            // Encrypt the plaintext
            (IPoint C1, IPoint C2) cipher = ECElGamalEncryption.Encrypt(_g, _publicKey, plaintextBytes);

            // Decrypt the ciphertext
            byte[] decryptedBytes = ECElGamalEncryption.DecryptData(_privateKey, cipher);

            // Check that the decrypted bytes match the original plaintext bytes
            Assert.That(decryptedBytes, Is.EqualTo(plaintextBytes));
        }

        [Test]
        public void TestEncryptDecryptString()
        {
            string plaintext = "Hello, world!";

            // Encrypt the plaintext
            (IPoint C1, IPoint C2) cipher = ECElGamalEncryption.Encrypt(_g, _publicKey, plaintext);

            // Decrypt the ciphertext
            string decrypted = ECElGamalEncryption.DecryptString(_privateKey, cipher);

            // Check that the decrypted string matches the original plaintext
            Assert.That(decrypted, Is.EqualTo(plaintext));
        }
    }
}
