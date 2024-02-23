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


using NUnit.Framework;

namespace SchnorrTests
{
    internal class SchnorrTests
    {
        private IGroup _g;
        private (IScalar prv, IPoint pub) KeyPair()
        {
            var prv = _g.Scalar();
            var pub = _g.Base().Mul(prv);
            return (prv, pub);
        }
        [SetUp]
        public void Setup()
        {
            _g = new Secp256k1Group();
        }

        [Test]
        public void TestSchnorrSignature()
        {
            var msg = System.Text.Encoding.UTF8.GetBytes("Hello Schnorr");

            var ( prv, pub ) = KeyPair();

            var s = Schnorr.Sign(_g, prv, msg);
            Assert.That(s, Is.Not.Null);

            Schnorr.Verify(_g, pub, msg, s);
            
            // wrong size
            var larger = s.Concat(new byte[] { 0x01, 0x02 }).ToArray();
            Assert.Throws<DkgError>(() => Schnorr.Verify(_g, pub, msg, larger));

            // wrong challenge
            var wrongEncoding = new byte[] { 243, 45, 180, 140, 73, 23, 41, 212, 250, 87, 157, 243,
                242, 19, 114, 161, 145, 47, 76, 26, 174, 150, 22, 177, 78, 79, 122, 30, 74,
                42, 156, 203 };
            var wrChall = new byte[s.Length];
            wrongEncoding.CopyTo(wrChall, 0);
            s.Skip(32).ToArray().CopyTo(wrChall, 32);
            Assert.Throws<DkgError>(() => Schnorr.Verify(_g, pub, msg, wrChall));

            // wrong response
            var wrResp = new byte[s.Length];
            s.Take(32).ToArray().CopyTo(wrResp, 0);
            wrongEncoding.CopyTo(wrResp, 32);
            Assert.Throws<DkgError>(() => Schnorr.Verify(_g, pub, msg, wrResp));

            // wrong public key
            (_, pub) = KeyPair();
            Assert.Throws<DkgError>(() => Schnorr.Verify(_g, pub, msg, s));
        }

        [Test]
        public void TestQuickSchnorrSignature()
        {
            var msg = System.Text.Encoding.UTF8.GetBytes("Hello Schnorr");
            var (prv, pub) = KeyPair();

            var s = Schnorr.Sign(_g,prv, msg);
            Assert.That(s, Is.Not.Null);

            Schnorr.Verify(_g, pub, msg, s); // No exception 
        }

        [Test]
        public void TestSchnorrMalleability()
        {
            /* l = 2^252+27742317777372353535851937790883648493, prime order of the base point */
            var L = new byte[] { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };
            var c = 0;

            var msg = System.Text.Encoding.UTF8.GetBytes("Hello Schnorr");
            var (prv, pub) = KeyPair();

            var s = Schnorr.Sign(_g, prv, msg);
            Assert.That(s, Is.Not.Null);

            Schnorr.Verify(_g, pub, msg, s);  // No exception

            // Add l to signature
            for (var i = 0; i < 32; i++)
            {
                c += s[32 + i] + L[i];
                s[32 + i] = (byte)c;
                c >>= 8;
            }
            Assert.Throws<DkgError>(() => Schnorr.Verify(_g, pub, msg, s));
        }
    }
}