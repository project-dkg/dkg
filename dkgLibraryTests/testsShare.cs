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
using dkg.poly;

namespace ShareTests
{
    internal class ShareComparerTests
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

        public class ShareTests
        {
            [Test]
            public void TestEquals()
            {
                Share share1 = new(10);
                Share share2 = new(20);
                Share share3 = new(20);

                Assert.Multiple(()=> { 
                    Assert.That(share1, Is.Not.EqualTo(null));
                    Assert.That(share1, Is.Not.EqualTo(share2));
                    Assert.That(share3, Is.EqualTo(share2));
                    Assert.That(share1.GetHashCode(), Is.Not.EqualTo(share2.GetHashCode()));
                    Assert.That(share3.GetHashCode(), Is.EqualTo(share2.GetHashCode()));
                });
            }

            [Test]
            public void TestMarshalUnmarshalBinary()
            {
                Share share1 = new(10);
                MemoryStream stream = new();
                share1.MarshalBinary(stream);
                Assert.That(stream.Length, Is.EqualTo(share1.MarshalSize()));
                stream.Position = 0;
                Share share2 = new(20);
                share2.UnmarshalBinary(stream);
                Assert.That(share1, Is.EqualTo(share2));
                Assert.That(share1.GetHashCode(), Is.EqualTo(share2.GetHashCode()));
            }
        }
    }
    public class PriShareTests
    {
        private PriShare _priShare;
        private IScalar _scalar;

        [SetUp]
        public void Setup()
        {
            _scalar = new Secp256k1Scalar().One();
            _priShare = new PriShare(5, _scalar);
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
            byte[] h = [201, 250, 51, 250, 139, 77, 119, 248, 174, 219, 8, 118, 32, 50, 
                        110, 22, 95, 163, 172, 125, 249, 85, 106, 184, 55, 79, 7, 81, 12, 70, 195, 252];
            var hash = _priShare.Hash();
            Assert.That(hash, Is.EqualTo(h));
        }

        [Test]
        public void TestToString()
        {
            var str = _priShare.ToString();
            Assert.That(str, Is.EqualTo("{PriShare: I = 5; V = {Secp256k1 Scalar: 1}}"));
        }

        [Test]
        public void TestEquals()
        {
            Secp256k1Scalar scalar2 = new();
            PriShare priShare2 = new(20, scalar2);
            PriShare priShare3 = new(20, scalar2);

            Assert.Multiple(() =>
            {
                Assert.That(_priShare, Is.Not.EqualTo(null));
                Assert.That(_priShare, Is.Not.EqualTo(priShare2));
                Assert.That(priShare3, Is.EqualTo(priShare2));
                Assert.That(_priShare.GetHashCode(), Is.Not.EqualTo(priShare2.GetHashCode()));
                Assert.That(priShare3.GetHashCode(), Is.EqualTo(priShare2.GetHashCode()));
            });
        }

        [Test]
        public void TestMarshalUnmarshalBinary()
        {
            MemoryStream stream = new();
            _priShare.MarshalBinary(stream);
            Assert.That(stream.Length, Is.EqualTo(_priShare.MarshalSize()));
            stream.Position = 0;
            PriShare share2 = new();
            share2.UnmarshalBinary(stream);
            Assert.Multiple(() =>
            {
                Assert.That(_priShare, Is.EqualTo(share2));
                Assert.That(_priShare.GetHashCode(), Is.EqualTo(share2.GetHashCode()));
            });
        }

        [Test]
        public void TestGetSetBytes()
        {
            byte[] bytes = _priShare.GetBytes();
            PriShare share2 = new();
            share2.SetBytes(bytes);
            Assert.Multiple(() =>
            {
                Assert.That(_priShare, Is.EqualTo(share2));
                Assert.That(_priShare.GetHashCode(), Is.EqualTo(share2.GetHashCode()));
            });
        }
    }

    public class PubShareTests
    {
        private PubShare _pubShare;
        private IPoint _point;

        [SetUp]
        public void Setup()
        {
            _point = new Secp256k1Point().Base();
            _pubShare = new PubShare(7, _point);
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
            byte[] h = [68, 20, 42, 98, 115, 0, 220, 153, 74, 10, 73, 145, 246, 129, 206, 170, 
                        86, 19, 209, 80, 155, 136, 255, 20, 213, 171, 156, 152, 249, 249, 108, 250];
            var hash = _pubShare.Hash();
            Assert.That(hash, Is.EqualTo(h));
        }

        [Test]
        public void TestToString()
        {
            var str = _pubShare.ToString();
            Assert.That(str, Is.EqualTo("{PubShare: I = 7; V = {Secp256k1 Point: " + 
                                        "(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798," + 
                                        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8," +
                                        "1,0)}}"));
        }
        [Test]
        public void TestEquals()
        {
            IPoint point2 = new Secp256k1Point().Base().Mul(new Secp256k1Scalar().SetInt64(37));
            PubShare pubShare2 = new(12, point2);
            PubShare pubShare3 = new(12, point2);

            Assert.Multiple(() =>
            {
                Assert.That(_pubShare, Is.Not.EqualTo(null));
                Assert.That(_pubShare, Is.Not.EqualTo(pubShare2));
                Assert.That(pubShare3, Is.EqualTo(pubShare2));
                Assert.That(_pubShare.GetHashCode(), Is.Not.EqualTo(pubShare2.GetHashCode()));
                Assert.That(pubShare3.GetHashCode(), Is.EqualTo(pubShare2.GetHashCode()));
            });
        }

        [Test]
        public void TestMarshalUnmarshalBinary()
        {
            MemoryStream stream = new();
            _pubShare.MarshalBinary(stream);
            Assert.That(stream.Length, Is.EqualTo(_pubShare.MarshalSize()));
            stream.Position = 0;
            PubShare share2 = new();
            share2.UnmarshalBinary(stream);
            Assert.Multiple(() =>
            {
                Assert.That(_pubShare, Is.EqualTo(share2));
                Assert.That(_pubShare.GetHashCode(), Is.EqualTo(share2.GetHashCode()));
            });
        }

        [Test]
        public void TestGetSetBytes()
        {
            byte[] bytes = _pubShare.GetBytes();
            PubShare share2 = new();
            share2.SetBytes(bytes);
            Assert.Multiple(() =>
            {
                Assert.That(_pubShare, Is.EqualTo(share2));
                Assert.That(_pubShare.GetHashCode(), Is.EqualTo(share2.GetHashCode()));
            });
        }
    }
}
