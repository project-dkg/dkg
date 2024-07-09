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
using Org.BouncyCastle.Crypto.Digests;

namespace VssTests
{
    internal class VssTests
    {
        private const int _nbVerifiers = 7;

        private int _goodT;

        private Secp256k1Group _g;
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
            _g = new Secp256k1Group();

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
            return new Dealer(_g, _dealerSec, _secret, [ .._verifiersPub], _vssThreshold);
        }

        private (Dealer, List<Verifier>) GenAll()
        {
            var dealer = GenDealer();
            var verifiers = new List<Verifier>(_nbVerifiers);
            for (var i = 0; i < _nbVerifiers; i++)
            {
                var v = new Verifier(_g, _verifiersSec[i], _dealerPub, [.. _verifiersPub]);
                verifiers.Add(v);
            }
            return (dealer, verifiers);
        }

        [Test]
        public void TestWhole()
        {
            var (dealer, verifiers) = GenAll();

            // 1. dispatch deal
            var resps = new Response[_nbVerifiers];
            var encDeals = dealer.EncryptedDeals();  // No Exception

            for (var i = 0; i < encDeals.Length; i++)
            {
                var d = encDeals[i];
                var resp = verifiers[i].ProcessEncryptedDeal(d); // No exception
                Assert.That(resp, Is.Not.Null); 
                resps[i] = resp;
            }

            // 2. dispatch responses
            foreach (var resp in resps)
            {
                for (var i = 0; i < verifiers.Count; i++)
                {
                    var v = verifiers[i];
                    if (resp.Index == (uint)i)
                        continue;
                    Assert.DoesNotThrow(() => v.ProcessResponse(resp));
                }
                // 2.1. check dealer (no justification here)
                var j = dealer.ProcessResponse(resp);  // No exception
                Assert.That(j, Is.Null); 
            }

            // 3. check certified
            foreach (var v in verifiers)
            {
                Assert.That(v.DealCertified(), Is.True);
            }

            // 4. collect deals
            Deal[] deals = new Deal[_nbVerifiers];
            for (var i = 0; i < verifiers.Count; i++)
            {
                var dd = verifiers[i].Deal();
                Assert.That(dd, Is.Not.Null);
                deals[i] = dd;
            }

            // 5. recover
            var sec = Dealer.RecoverSecret(_g, deals, VssTools.MinimumT(_nbVerifiers));
            Assert.That(sec, Is.Not.Null);
            Assert.That(sec, Is.EqualTo(_secret));

            var priPoly = dealer.SecretPoly;
            var priCoeffs = priPoly.Coeffs;
            Assert.That(_secret, Is.EqualTo(priCoeffs[0]));
        }

        [Test]
        public void TestDealerNew()
        {
            Dealer dealer = new(_g, _dealerSec, _secret, [.. _verifiersPub], _goodT);

            int[] badTs = [0, 1, -4];
            foreach (int badT in badTs)
            {
                Assert.Throws<ArgumentException>(() =>
                    {
                        Dealer dealer = new(_g, _dealerSec, _secret, [.. _verifiersPub], badT);
                    });
            }
        }

        [Test]
        public void TestVerifierNew()
        {
            Random Random = new();
            int randIdx = Random.Next(_verifiersPub.Count);
            Verifier v = new(_g, _verifiersSec[randIdx], _dealerPub, [.. _verifiersPub]);

            IScalar wrongKey = _g.Scalar();
            Assert.Throws<ArgumentException>(() =>
            {
                Verifier wrongVerifier = new(_g, wrongKey, _dealerPub, [.. _verifiersPub]);
            });
        }


        [Test]
        public void TestShare()
        {
            var (dealer, verifiers) = GenAll();
            var ver = verifiers[0];
            var deal = dealer.EncryptedDeal(0);

            var resp = ver.ProcessEncryptedDeal(deal);
            Assert.That(resp, Is.Not.Null);
            Assert.That(resp.Status, Is.EqualTo(ResponseStatus.Approval));

            var aggr = ver.Aggregator;
            var sessionId = VssTools.CreateSessionId(_dealerPub, [.. _verifiersPub], [.. dealer.Deals[0].Commitments], dealer.T);

            for (int i = 1; i < aggr.T - 1; i++)
            {
                aggr.Responses[i] = new Response(sessionId, i) {  Status = ResponseStatus.Approval };
            }

            // Not enough approvals
            Assert.That(ver.GetDeal(), Is.Null);

            aggr.Responses[aggr.T] = new Response(sessionId, 0) { Status = ResponseStatus.Approval };

            // Timeout all other (i > t) verifiers
            ver.SetTimeout();

            // Deal not certified
            aggr.BadDealer = true;
            Assert.That(ver.GetDeal(), Is.Null);
            aggr.BadDealer = false;
            Assert.That(ver.GetDeal(), Is.Not.Null);
        }
        [Test]
        public void TestAggregatorDealCertified()
        {
            var dealer = GenDealer();
            var aggr = dealer.Aggregator;

            var sessionId = VssTools.CreateSessionId(_dealerPub, [.. _verifiersPub], [.. dealer.Deals[0].Commitments], dealer.T);

            for (int i = 0; i < aggr.T; i++)
            {
                aggr.Responses[i] = new Response(sessionId, i) { Status = ResponseStatus.Approval };
            }

            // Mark remaining verifiers as timed-out
            dealer.SetTimeout();

            IPoint sc = _g.Base().Mul(_secret);
            Assert.Multiple(() =>
            {
                Assert.That(aggr.DealCertified(), Is.True);
                Assert.That(dealer.SecretCommit(), Is.EqualTo(sc));
            });

            // Bad dealer response
            aggr.BadDealer = true;
            Assert.Multiple(() =>
            {
                Assert.That(aggr.DealCertified(), Is.False);
                Assert.That(dealer.SecretCommit(), Is.Null);
            });

            // Reset dealer status
            aggr.BadDealer = false;

            // Inconsistent state on purpose
            // Too much complaints
            for (int i = 0; i < aggr.T; i++)
            {
                aggr.Responses[i] = new Response(sessionId, i) { Status = ResponseStatus.Complaint };
            }
            Assert.That(aggr.DealCertified(), Is.False);
        }

        [Test]
        public void TestDecryptDeal()
        {
            var (dealer, verifiers) = GenAll();

            int randIdx = _randomReader.ReadInt32() % (dealer.T - 1);
            randIdx = randIdx < 0 ? -randIdx : randIdx;

            Verifier verifier = verifiers[randIdx];
            var d = dealer.Deals[randIdx];

            EncryptedDeal encryptedDeal = dealer.EncryptedDeal(randIdx);
            Assert.That(encryptedDeal, Is.Not.Null);
// !!! Assert.IsNull(encryptedDeal.LastProcessingError);

            // all fine
            Deal? decryptedDeal = verifier.DecryptDeal(encryptedDeal);
            Assert.Multiple(() =>
            {
                Assert.That(dealer.Deals[randIdx], Is.EqualTo(decryptedDeal)); // No exception
                Assert.That(verifier.LastProcessingError, Is.Null);
            });

            // wrong dh key
            var goodDh = encryptedDeal.DHKey;
            encryptedDeal.DHKey = _g.Point().Null().GetBytes();
            Assert.Multiple(() =>
            {
                Assert.That(verifier.DecryptDeal(encryptedDeal), Is.Null);
                Assert.That(verifier.LastProcessingError, Is.Not.Null);
            });
            encryptedDeal.DHKey = goodDh;

            // wrong signature
            var goodSig = encryptedDeal.Signature;
            encryptedDeal.Signature = _randomReader.ReadBytes(goodSig.Length * 2);
            Assert.Multiple(() =>
            {
                Assert.That(verifier.DecryptDeal(encryptedDeal), Is.Null);
                Assert.That(verifier.LastProcessingError, Is.Not.Null);
            });
            encryptedDeal.Signature = goodSig;

            // wrong ciphertext
            var goodCipher = encryptedDeal.Cipher;
            encryptedDeal.Cipher = _randomReader.ReadBytes(goodCipher.Length);
            Assert.Multiple(() =>
            {
                Assert.That(verifier.DecryptDeal(encryptedDeal), Is.Null);
                Assert.That(verifier.LastProcessingError, Is.Not.Null);
            });
            encryptedDeal.Cipher = goodCipher;

            // wrong tag
            var goodTag = encryptedDeal.Tag;
            encryptedDeal.Tag = _randomReader.ReadBytes(goodTag.Length);
            Assert.Multiple(() =>
            {
                Assert.That(verifier.DecryptDeal(encryptedDeal), Is.Null);
                Assert.That(verifier.LastProcessingError, Is.Not.Null);
            });
            encryptedDeal.Tag = goodTag;
        }

        [Test]
        public void TestReceiveDeal()
        {
            var (dealer, verifiers) = GenAll();

            int randIdx = _randomReader.ReadInt32() % (dealer.T - 1);
            randIdx = randIdx < 0 ? -randIdx : randIdx;

            var verifier = verifiers[randIdx];
            var d = dealer.Deals[randIdx];

            IPoint[] commitments = [.. dealer.Deals[0].Commitments];
            byte[] sid = VssTools.CreateSessionId(_dealerPub, [.. _verifiersPub], commitments, dealer.T);
            Assert.That(sid, Is.Not.Null);

            var encryptedDeal = dealer.EncryptedDeal(randIdx);

            // correct deal
            var resp = verifier.ProcessEncryptedDeal(encryptedDeal); // No exception
            Assert.That(resp, Is.Not.Null);
            Assert.Multiple(() =>
            {
                Assert.That(verifier.LastProcessingError, Is.Null);
                Assert.That(resp.Status, Is.EqualTo(ResponseStatus.Approval));
                Assert.That(resp.Index, Is.EqualTo(verifier.Index));
                Assert.That(resp.SessionId, Is.EqualTo(dealer.SessionId));
                Schnorr.Verify(_g, verifier.PublicKey, resp.GetBytesForSignature(), resp.Signature);
                Assert.That(resp, Is.EqualTo(verifier.Responses()[verifier.Index]));
            });

            // wrong encryption
            var goodSig = encryptedDeal.Signature;
            encryptedDeal.Signature = _randomReader.ReadBytes(32);
            Assert.Multiple(() =>
            {
                Assert.That(verifier.ProcessEncryptedDeal(encryptedDeal), Is.Null);
                Assert.That(verifier.LastProcessingError, Is.Not.Null);
            });
            encryptedDeal.Signature = goodSig;

            // wrong index
            var goodIdx = d.SecShare.I;
            d.SecShare.I = (goodIdx - 1) % _nbVerifiers;
            encryptedDeal = dealer.EncryptedDeal(0);
            Assert.Multiple(() =>
            {
                Assert.That(verifier.ProcessEncryptedDeal(encryptedDeal), Is.Null);
                Assert.That(verifier.LastProcessingError, Is.Not.Null);
            });
            d.SecShare.I = goodIdx;

            // valid complaint
            // wrong commitments
            var goodCommit = d.Commitments[randIdx];
            d.Commitments[randIdx] = _g.Point();
            encryptedDeal = dealer.EncryptedDeal(randIdx);

            verifier.Aggregator.Deal = null;
            verifier.Responses().Remove(verifier.Index);
            
            resp = verifier.ProcessEncryptedDeal(encryptedDeal);
            Assert.That(resp, Is.Not.Null);
            Assert.Multiple(() =>
            {
                Assert.That(verifier.LastProcessingError, Is.Null);
                Assert.That(resp.Status, Is.EqualTo(ResponseStatus.Complaint));
                Assert.That(resp.Complaint, Is.EqualTo(ComplaintCode.ShareDoesNotVerify));
            });
            d.Commitments[randIdx] = goodCommit;

            encryptedDeal = dealer.EncryptedDeal(randIdx);
            verifier.Aggregator.Deal = null;
            verifier.Responses().Remove(verifier.Index);
            resp = verifier.ProcessEncryptedDeal(encryptedDeal);
            Assert.That(resp, Is.Not.Null);
            Assert.Multiple(() =>
            {
                Assert.That(verifier.LastProcessingError, Is.Null);
                Assert.That(resp.Status, Is.EqualTo(ResponseStatus.Approval));
                Assert.That(resp.Complaint, Is.EqualTo(ComplaintCode.NoComplaint));
            });

            // valid complaint
            // already seen twice
            resp = verifier.ProcessEncryptedDeal(encryptedDeal);
            Assert.Multiple(() =>
            {
                Assert.That(resp, Is.Null);
                Assert.That(verifier.LastProcessingError, Is.Not.Null);
            });
        }

        [Test]
        public void TestAggregatorVerifyJustification()
        {
            var (dealer, verifiers) = GenAll();
            var verifier = verifiers[0];
            var deal = dealer.Deals[0];

            var wrongV = _g.Scalar();
            var goodV = deal.SecShare.V;
            deal.SecShare.V = wrongV;
            var encD = dealer.EncryptedDeal(0);
            var resp = verifier.ProcessEncryptedDeal(encD);
            Assert.That(resp, Is.Not.Null);
            Assert.Multiple(() =>
            {
                Assert.That(resp.Status, Is.EqualTo(ResponseStatus.Complaint));
                Assert.That(resp, Is.EqualTo(verifier.Responses()[verifier.Index]));
            });
            deal.SecShare.V = goodV;

            var j = dealer.ProcessResponse(resp);
            Assert.That(j, Is.Not.Null);
            goodV = j.Deal.SecShare.V;
            j.Deal.SecShare.V = wrongV;
            Assert.Multiple(() =>
            {
                Assert.That(verifier.ProcessJustification(j), Is.Not.Null);
                Assert.That(verifier.Aggregator.BadDealer, Is.True);
            });
            j.Deal.SecShare.V = goodV;
            verifier.Aggregator.BadDealer = false;
            Assert.That(verifier.ProcessJustification(j), Is.Null);

            resp.SessionId = _randomReader.ReadBytes(resp.SessionId.Length);
            Assert.That(verifier.ProcessJustification(j), Is.Not.Null);
            resp.SessionId = dealer.SessionId;

            verifier.Responses().Remove(verifier.Index);
            Assert.That(verifier.ProcessJustification(j), Is.Not.Null);
            verifier.Responses()[verifier.Index] = resp;
        }

        [Test]
        public void TestAggregatorVerifyResponseDuplicate()
        {
            var (dealer, verifiers) = GenAll();
            var v1 = verifiers[0];
            var v2 = verifiers[1];
            var encD1 = dealer.EncryptedDeal(0);
            var encD2 = dealer.EncryptedDeal(1);

            var resp1 = v1.ProcessEncryptedDeal(encD1);
            Assert.That(resp1, Is.Not.Null);
            Assert.That(resp1.Status, Is.EqualTo(ResponseStatus.Approval));
            var resp2 = v2.ProcessEncryptedDeal(encD2);
            Assert.That(resp2, Is.Not.Null);
            Assert.That(resp2.Status, Is.EqualTo(ResponseStatus.Approval));
            var err = v1.ProcessResponse(resp2);
            Assert.Multiple(() =>
            {
                Assert.That(err, Is.Null);
                Assert.That(v1.Responses().TryGetValue(v2.Index, out Response? r), Is.True);
                Assert.That(r, Is.EqualTo(resp2));
            });

            err = v1.ProcessResponse(resp2);
            // Let attempt to add duplicate be no-op
            // Assert.That(err, Is.Not.Null);
            Assert.That(err, Is.Null);

            v1.Responses().Remove(v2.Index);
            var sessionId = VssTools.CreateSessionId(_dealerPub, [.. _verifiersPub], [.. dealer.Deals[v2.Index].Commitments], dealer.T);
            v1.Responses()[v2.Index] = new Response(sessionId, v2.Index) { Status = ResponseStatus.Approval };
            err = v1.ProcessResponse(resp2);
            // Let attempt to add duplicate be no-op
            // Assert.That(err, Is.Not.Null);
            Assert.That(err, Is.Null);
        }

        [Test]
        public void TestAggregatorVerifyResponse()
        {
            var (dealer, verifiers) = GenAll();
            var v = verifiers[0];
            var deal = dealer.Deals[0];
            var (wrongSec, _) = KeyPair();
            deal.SecShare.V = wrongSec;
            var encD = dealer.EncryptedDeal(0);

            var resp = v.ProcessEncryptedDeal(encD);
            Assert.That(resp, Is.Not.Null);
            Assert.Multiple(() =>
            {
                Assert.That(resp.Status, Is.EqualTo(ResponseStatus.Complaint));
                Assert.That(v.Aggregator, Is.Not.Null);
                Assert.That(dealer.SessionId, Is.EqualTo(resp.SessionId));
            });

            var aggr = v.Aggregator;
            Assert.Multiple(() =>
            {
                Assert.That(aggr.Responses.TryGetValue(v.Index, out Response? r), Is.True);
                Assert.That(r, Is.Not.Null);
                Assert.That(r?.Status, Is.EqualTo(ResponseStatus.Complaint));
            });


            resp.Index = _verifiersPub.Count;
            var sig = Schnorr.Sign(_g, v.LongTermKey, resp.GetBytesForSignature());
            resp.Signature = sig;
            Assert.That(aggr.VerifyResponse(resp), Is.Not.Null);
            resp.Index = 0;

            var goodSig = resp.Signature;
            resp.Signature = _randomReader.ReadBytes(goodSig.Length);
            Assert.That(aggr.VerifyResponse(resp), Is.Not.Null);
            resp.Signature = goodSig;

            var wrongID = _randomReader.ReadBytes(resp.SessionId.Length);
            var goodID = resp.SessionId;
            resp.SessionId = wrongID;
            Assert.That(aggr.VerifyResponse(resp), Is.Not.Null);
            resp.SessionId = goodID;
        }
        [Test]
        public void TestAggregatorAllResponses()
        {
            var dealer = GenDealer();
            var aggr = dealer.Aggregator;

            for (int i = 0; i < aggr.T; i++)
            {
                var sessionId = VssTools.CreateSessionId(_dealerPub, [.. _verifiersPub], [.. dealer.Deals[i].Commitments], dealer.T);
                aggr.Responses[i] = new Response(sessionId, i) { Status = ResponseStatus.Approval };
            }
            Assert.That(aggr.DealCertified(), Is.False);

            for (int i = aggr.T; i < _nbVerifiers; i++)
            {
                var sessionId = VssTools.CreateSessionId(_dealerPub, [.. _verifiersPub], [.. dealer.Deals[i].Commitments], dealer.T);
                aggr.Responses[i] = new Response(sessionId, i) { Status = ResponseStatus.Approval };
            }

            Assert.Multiple(() =>
            {
                Assert.That(aggr.DealCertified(), Is.True);
                Assert.That(dealer.SecretCommit(), Is.EqualTo(_g.Base().Mul(_secret)));
            });
        }

        [Test]
        public void TestDealerTimeout()
        {
            var dealer = GenDealer();
            var aggr = dealer.Aggregator;

            for (int i = 0; i < aggr.T; i++)
            {
                var sessionId = VssTools.CreateSessionId(_dealerPub, [.. _verifiersPub], [.. dealer.Deals[i].Commitments], dealer.T);
                aggr.Responses[i] = new Response(sessionId, i) { Status = ResponseStatus.Approval };
            }
            Assert.That(aggr.DealCertified(), Is.False);

            // Tell dealer to consider other verifiers timed-out
            dealer.SetTimeout();
            Assert.Multiple(() =>
            {

                // Deal should be certified
                Assert.That(aggr.DealCertified(), Is.True);
                Assert.That(dealer.SecretCommit(), Is.Not.Null);
            });
        }

        [Test]
        public void TestVerifierTimeout()
        {
            var (dealer, verifiers) = GenAll();
            var v = verifiers[0];

            var encDeal = dealer.EncryptedDeal(0);

            Assert.That(encDeal, Is.Not.Null);

            // Make verifier create it's Aggregator by processing EncDeal
            var resp = v.ProcessEncryptedDeal(encDeal); // No exception
            var aggr = v.Aggregator;

            // Add T responses
            for (int i = 0; i < aggr.T; i++)
            {
                var sessionId = VssTools.CreateSessionId(_dealerPub, [.. _verifiersPub], [.. dealer.Deals[i].Commitments], dealer.T);
                aggr.Responses[i] = new Response(sessionId, i) { Status = ResponseStatus.Approval };
            }
            Assert.That(aggr.DealCertified(), Is.False);

            // Trigger time out, thus adding StatusComplaint to all
            // remaining verifiers
            v.SetTimeout();

            // Deal must be certified now
            Assert.Multiple(() =>
            {
                Assert.That(aggr.DealCertified(), Is.True);
                Assert.That(v.Aggregator.Deal, Is.Not.Null);
            });
        }

        [Test]
        public void TestAggregatorVerifyDeal()
        {
            var dealer = GenDealer();
            var aggr = dealer.Aggregator;
            var deals = dealer.Deals;

            // OK
            var deal = deals[0];
            var Complaint = aggr.VerifyDeal(deal, true);
            Assert.Multiple(() =>
            {
                Assert.That(Complaint, Is.EqualTo(ComplaintCode.NoComplaint));
                Assert.That(aggr.Deal, Is.Not.Null);
            });

            // already received deal
            Complaint = aggr.VerifyDeal(deal, true);
            Assert.That(Complaint, Is.EqualTo(ComplaintCode.AlreadyProcessed));

            // wrong T
            var wrongT = 1;
            var goodT = deal.T;
            deal.T = wrongT;
            Assert.That(aggr.VerifyDeal(deal, false), Is.EqualTo(ComplaintCode.InvalidThreshold));
            deal.T = goodT;

            // wrong SessionID
            var goodSid = deal.SessionId;
            deal.SessionId = new byte[32];
            Assert.That(aggr.VerifyDeal(deal, false), Is.EqualTo(ComplaintCode.SessionIdDoesNotMatch));
            deal.SessionId = goodSid;

            // index different in one share
            var goodI = deal.SecShare.I;
            deal.SecShare.I = goodI + 1;
            Assert.That(aggr.VerifyDeal(deal, false), Is.EqualTo(ComplaintCode.ShareDoesNotVerify));
            deal.SecShare.I = goodI;

            // index not in bounds
            deal.SecShare.I = -1;
            Assert.That(aggr.VerifyDeal(deal, false), Is.EqualTo(ComplaintCode.IndexOutOfBound));
            deal.SecShare.I = _verifiersPub.Count;
            Assert.That(aggr.VerifyDeal(deal, false), Is.EqualTo(ComplaintCode.IndexOutOfBound));

            // shares invalid in respect to the commitments
            var (wrongSec, _) = KeyPair();
            deal.SecShare.I = goodI;
            deal.SecShare.V = wrongSec;
            Assert.That(aggr.VerifyDeal(deal, false), Is.EqualTo(ComplaintCode.ShareDoesNotVerify));
        }

        [Test]
        public void TestAggregatorAddComplaint()
        {
            var dealer = GenDealer();
            var aggr = dealer.Aggregator;

            var idx = 1;
            var sessionId = VssTools.CreateSessionId(_dealerPub, [.. _verifiersPub], [.. dealer.Deals[idx].Commitments], dealer.T);
            var c = new Response(sessionId, idx) { Status = ResponseStatus.Complaint };
            Assert.Multiple(() =>
            {
                Assert.That(aggr.AddResponse(c), Is.Null);
                Assert.That(c, Is.EqualTo(aggr.Responses[idx]));
                // Let add duplicate be no-op
                // Assert.That(aggr.AddResponse(c), Is.Not.Null);
                Assert.That(aggr.AddResponse(c), Is.Null);

            });
            aggr.Responses.Remove(idx);
        }

        [Test]
        public void TestSessionId()
        {
            Dealer dealer = GenDealer();
            IPoint[] commitments = [.. dealer.Deals[0].Commitments];
            byte[] sid = VssTools.CreateSessionId(_dealerPub, [.. _verifiersPub], commitments, dealer.T);
            Assert.That(sid, Is.Not.Null);

            byte[] sid2 = VssTools.CreateSessionId(_dealerPub, [.. _verifiersPub], commitments, dealer.T);
            Assert.That(sid, Is.EqualTo(sid2));

            IPoint wrongDealerPub = _dealerPub.Add(_dealerPub);
            byte[] sid3 = VssTools.CreateSessionId(wrongDealerPub, [.. _verifiersPub], commitments, dealer.T);
            Assert.That(sid3, Is.Not.Null);
            Assert.That(sid3, Is.Not.EqualTo(sid2));
        }

        [Test]
        public void TestDhExchange()
        {
            IPoint pub = _g.Base();
            IScalar priv = _g.Scalar();
            IPoint point = DhHelper.DhExchange(priv, pub);
            Assert.That(point, Is.EqualTo(_g.Base().Mul(priv)));
        }

        [Test]
        public void TestContext()
        {
            byte[] context = DhHelper.Context(_dealerPub, [.. _verifiersPub]);
            Sha256Digest digest = new();
            Assert.That(context, Has.Length.EqualTo(digest.GetDigestSize()));
        }
    }
}
