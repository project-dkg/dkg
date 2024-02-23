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

namespace DealMarshallingTests
{
    internal class TestsDealMarshalling
    {
        private const int _nbVerifiers = 3;

        private int _goodT;

        private IGroup _g;
        private HashAlgorithm _hash;
        private IPoint _dealerPub;
        private IScalar _dealerSec;
        private IScalar _secret;
        private int _vssThreshold;

        List<IPoint> _verifiersPub;
        List<IScalar> _verifiersSec;

        RandomStream _randomStream;
        BinaryReader _randomReader;


        [SetUp]
        public void Setup()
        {
            _g = Suite.G;
            _hash = System.Security.Cryptography.SHA256.Create();

            (_dealerSec, _dealerPub) = KeyPair();
            (_secret, _) = KeyPair();
            _vssThreshold = VssTools.MinimumT(_nbVerifiers);

            _verifiersPub = [];
            _verifiersSec = [];

            (_verifiersSec, _verifiersPub) = GenCommits(_nbVerifiers);

            _goodT = VssTools.MinimumT(_nbVerifiers);

            _randomStream = new();
            _randomReader = new(_randomStream);

        }
        private (IScalar prv, IPoint pub) KeyPair()
        {
            var prv = _g.Scalar();
            var pub = _g.Base().Mul(prv);
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

        private Dealer GenDealer()
        {
            return new Dealer(_hash, _dealerSec, _secret, [.. _verifiersPub], _vssThreshold);
        }

        private (Dealer, List<Verifier>) GenAll()
        {
            var dealer = GenDealer();
            var verifiers = new List<Verifier>(_nbVerifiers);
            for (var i = 0; i < _nbVerifiers; i++)
            {
                var v = new Verifier(_hash, _verifiersSec[i], _dealerPub, [.. _verifiersPub]);
                verifiers.Add(v);
            }
            return (dealer, verifiers);
        }

        [Test]
        public void TestDealEquals()
        {
            Dealer dealer = GenDealer();
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
        public void TestDealMarshaUnmarshal()
        {
            Dealer dealer = GenDealer();
            Deal d = new();

            MemoryStream stream = new();
            dealer.Deals[0].MarshalBinary(stream);
            Assert.That(stream.Length, Is.EqualTo(dealer.Deals[0].MarshalSize()));
            stream.Position = 0;
            d.UnmarshalBinary(stream);
            Assert.That(dealer.Deals[0], Is.EqualTo(d));
        }

        [Test]
        public void TestEncryptedDealMarhalling()
        {
            var dealer = GenDealer();
            var encDeal = dealer.EncryptedDeals()[0];

            byte[] bs = encDeal.GetBytes();

            var encDeal2 = new EncryptedDeal();
            encDeal2.SetBytes(bs);

            Assert.That(encDeal, Is.EqualTo(encDeal2));
            Assert.That(encDeal, Is.Not.EqualTo(null));
        }

        [Test]
        public void TestDistDealMarhalling()
        {
            var dealer = GenDealer();
            var encDeal = dealer.EncryptedDeals()[0];
            var distDeal = new DistDeal(0, encDeal);
            distDeal.Signature = Schnorr.Sign(Suite.G, _hash, _dealerSec, distDeal.GetBytesForSignature());

            byte[] bs = distDeal.GetBytes();

            var distDeal2 = new DistDeal();
            distDeal2.SetBytes(bs);

            Assert.That(distDeal, Is.EqualTo(distDeal2));
            Assert.That(distDeal, Is.Not.EqualTo(null));
        }

        [Test]
        public void TestResponseMarshalling()
        {
            var (dealer, verifiers) = GenAll();

            int randIdx = _randomReader.ReadInt32() % (dealer.T - 1);
            randIdx = randIdx < 0 ? -randIdx : randIdx;

            var verifier = verifiers[randIdx];
            var d = dealer.Deals[randIdx];

            IPoint[] commitments = [.. dealer.Deals[0].Commitments];
            byte[] sid = VssTools.CreateSessionId(_hash, _dealerPub, [.. _verifiersPub], commitments, dealer.T);
            Assert.That(sid, Is.Not.Null);

            var encryptedDeal = dealer.EncryptedDeal(randIdx);

            // correct deal
            var resp = verifier.ProcessEncryptedDeal(encryptedDeal); // No exception
            Assert.That(resp, Is.Not.Null);

            byte[] rb = resp.GetBytes();
            var uResp = new Response();
            uResp.SetBytes(rb);
            Assert.That(resp, Is.EqualTo(uResp));
        }
    }
}
