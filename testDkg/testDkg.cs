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

using System.Net.Sockets;

namespace DkgTests
{
    [TestFixture]
    public class DkgTests
    {
        private const int nbVerifiers = 7;

        private int _goodT;

        private IGroup _g;
        private IPoint _dealerPub;
        private IScalar _dealerSec;
        private IScalar _secret;
        private int _vssThreshold;

        List<IPoint> _verifiersPub;
        List<IScalar> _verifiersSec;

        [SetUp]
        public void Setup()
        {
            _g = Suite.G;
            (_dealerSec, _dealerPub) = KeyPair();
            (_secret, _) = KeyPair();
            _vssThreshold = Dealer.MinimumT(nbVerifiers);

            _verifiersPub = [];
            _verifiersSec = [];

            (_verifiersSec, _verifiersPub) = GenCommits(nbVerifiers);

            _goodT = Dealer.MinimumT(nbVerifiers);
        }
        private (IScalar prv, IPoint pub) KeyPair()
        {
            var prv = _g.Scalar();
            var pub = _g.Point().Base().Mul(prv);
            return (prv, pub);
        }

        private (List<IScalar>, List<IPoint>) GenCommits(int n)
        {
            List<IScalar> secrets = new(n);
            List<IPoint> publics = new(n);

            for (int i = 0; i < n; i++)
            {
                var (prv, pub) = KeyPair();
                secrets.Add(prv);
                publics.Add(pub);
            }
            return (secrets, publics);
        }

        [Test]
        public void TestVSSDealerNew()
        {
            int goodT = Dealer.MinimumT(nbVerifiers);
            Dealer dealer = new(_dealerSec, _secret, _verifiersPub, goodT);

            int[] badTs = [0, 1, -4];
            foreach (int badT in badTs)
            {
                Assert.Throws<ArgumentException>(() =>
                    {
                        Dealer dealer = new(_dealerSec, _secret, _verifiersPub, badT);
                    });
            }
        }

        [Test]
        public void TestVssVerifierNew()
        {
            Random Random = new();
            int randIdx = Random.Next(_verifiersPub.Count);
            Verifier v = new(_verifiersSec[randIdx], _dealerPub, _verifiersPub);

            IScalar wrongKey = _g.Scalar();
            Assert.Throws<ArgumentException>(() =>
            {
                Verifier wrongVerifier = new Verifier(wrongKey, _dealerPub, _verifiersPub);
            });
        }

        [Test]
        public void TestVssSessionId()
        {
            Dealer dealer = new(_dealerSec, _secret, _verifiersPub, _vssThreshold);
            IPoint[] commitments = [.. dealer.Deals[0].Commitments];
            byte[] sid = dealer.CreateSessionId(_dealerPub, _verifiersPub, commitments, dealer.T);
            Assert.That(sid, Is.Not.Null);

            byte[] sid2 = dealer.CreateSessionId(_dealerPub, _verifiersPub, commitments, dealer.T);
            Assert.That(sid, Is.EqualTo(sid2));

            IPoint wrongDealerPub = _dealerPub.Add(_dealerPub);
            byte[] sid3 = dealer.CreateSessionId(wrongDealerPub, _verifiersPub, commitments, dealer.T);
            Assert.That(sid3, Is.Not.Null);
            Assert.That(sid3, Is.Not.EqualTo(sid2));
        }

        [Test]
        public void TestVssDhExchange()
        {
            IPoint pub = _g.Point().Base();
            IScalar priv = _g.Scalar();
            IPoint point = DhHelper.DhExchange(priv, pub);
            Assert.That(point, Is.EqualTo(_g.Point().Base().Mul(priv)));
        }

        [Test]
        public void TestVssContext()
        {
            byte[] context = DhHelper.Context(Suite.Hash, _dealerPub, _verifiersPub);
            Assert.That(context, Has.Length.EqualTo(Suite.Hash.HashSize / 8));
        }

        [Test]
        public void TestVSSDealEquals()
        {
            Dealer dealer = new(_dealerSec, _secret, _verifiersPub, _goodT);
            Deal d = new();

            Assert.Multiple(() =>
            {
                Assert.That(dealer.Deals[0], Is.Not.EqualTo(null));
                Assert.That(dealer.Deals[1], Is.Not.EqualTo(dealer.Deals[0]));
                Assert.That(dealer.Deals[1], Is.Not.EqualTo(d));
                Assert.That(dealer.Deals[1].GetHashCode(), Is.Not.EqualTo(dealer.Deals[0].GetHashCode()));
                Assert.That(dealer.Deals[1].GetHashCode(), Is.Not.EqualTo(d.GetHashCode()));
            });
        }

        [Test]
        public void TestVSSDealMarshaUnmarshal()
        {
            Dealer dealer = new(_dealerSec, _secret, _verifiersPub, _goodT);
            Deal d = new();

            MemoryStream stream = new();
            dealer.Deals[0].MarshalBinary(stream);
            Assert.That(stream.Length, Is.EqualTo(dealer.Deals[0].MarshalSize()));
            stream.Position = 0;
            d.UnmarshalBinary(stream);
            Assert.That(dealer.Deals[0], Is.EqualTo(d));
        }

        [Test]
        public void TestVSSDealEncryptDecrypt()
        {
            Dealer dealer = new(_dealerSec, _secret, _verifiersPub, _goodT);
            var encrypted = dealer.EncryptedDeal(0);
            Assert.That(encrypted, Is.Not.Null);
        }
    }
}
