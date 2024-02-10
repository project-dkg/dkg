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

namespace ShareTests
{
    public class ShareComparerTests
    {
        private ShareComparer _comparer;

        [SetUp]
        public void Setup()
        {
            _comparer = new ShareComparer();
        }

        [Test]
        public void TestCompareEqualShares()
        {
            Share share1 = new(10);
            Share share2 = new(10);
            int result = _comparer.Compare(share1, share2);
            Assert.That(result, Is.EqualTo(0));
        }

        [Test]
        public void TestCompareDifferentShares1()
        {
            Share share1 = new(10);
            Share share2 = new(20);
            int result = _comparer.Compare(share1, share2);
            Assert.That(result, Is.EqualTo(-1));
        }

        [Test]
        public void TestCompareDifferentShares2()
        {
            Share share1 = new(30);
            Share share2 = new(20);
            int result = _comparer.Compare(share1, share2);
            Assert.That(result, Is.EqualTo(1));
        }
        [Test]
        public void TestCompareNullShares()
        {
            Share? share1 = null;
            Share? share2 = new(10);
            Assert.Throws<ArgumentNullException>(() => _comparer.Compare(share1, share2));
        }

        [Test]
        public void TestCompareNullNotNullShares()
        {
            Share? share1 = new(10);
            Share? share2 = null;
            Assert.Throws<ArgumentNullException>(() => _comparer.Compare(share1, share2));
        }
    }
    public class PriShareTests
    {
        private PriShare _priShare;
        private IScalar _scalar;
        private HashAlgorithm _hashAlgorithm;

        [SetUp]
        public void Setup()
        {
            _scalar = new Secp256k1Scalar().One();
            _priShare = new PriShare(5, _scalar);
            _hashAlgorithm = SHA256.Create();
        }

        [Test]
        public void TestSetGetShareValue()
        {
            Assert.Multiple(() =>
            {
                Assert.That(_priShare.I, Is.EqualTo(5));
                Assert.That(_priShare.V, Is.EqualTo(_scalar));
            });
        }

        [Test]
        public void TestHash()
        {
            byte[] h = [75, 245, 18, 47, 52, 69, 84, 197, 59, 222, 46, 187, 140, 210, 183, 227, 
                        209, 96, 10, 214, 49, 195, 133, 165, 215, 204, 226, 60, 119, 133, 69, 154, 5, 0, 0, 0];
            var hash = _priShare.Hash(_hashAlgorithm);
            Assert.That(hash, Is.EqualTo(h));
        }

        [Test]
        public void TestToString()
        {
            var str = _priShare.ToString();
            Assert.That(str, Is.EqualTo("{PriShare: I = 5; V = {Secp256k1 Scalar: Value = 1}}"));
        }
    }

    public class PubShareTests
    {
        private PubShare _pubShare;
        private IPoint _point;
        private HashAlgorithm _hashAlgorithm;

        [SetUp]
        public void Setup()
        {
            _point = new Secp256k1Point().Base();
            _pubShare = new PubShare(7, _point);
            _hashAlgorithm = SHA256.Create();
        }

        [Test]
        public void TestSetGetShareValue()
        {
            Assert.Multiple(() =>
            {
                Assert.That(_pubShare.I, Is.EqualTo(7));
                Assert.That(_pubShare.V, Is.EqualTo(_point));
            });
        }

        [Test]
        public void TestHash()
        {
            byte[] h = [15, 113, 91, 175, 93, 76, 46, 211, 41, 120, 92, 239, 41, 229, 98, 247, 52, 
                        136, 200, 162, 187, 157, 188, 87, 0, 179, 97, 213, 75, 155, 5, 84, 7, 0, 0, 0];
            var hash = _pubShare.Hash(_hashAlgorithm);
            Assert.That(hash, Is.EqualTo(h));
        }

        [Test]
        public void TestToString()
        {
            var str = _pubShare.ToString();
            Assert.That(str, Is.EqualTo("{PubShare: I = 7; V = {Secp256k1 Point: " + 
                                        "X = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, " + 
                                        "Y = 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8}}"));
        }
    }
}
