
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

using dkg;
using Org.BouncyCastle.Pqc.Crypto.Lms;

namespace DkgTests
{
    internal class TestDkgPedersen
    {
        private const int _defaultN = 5;
        private static int _defaultT => VssTools.MinimumT(_defaultN);

        private IGroup _g = Suite.G;

        RandomStream _randomStream;
        BinaryReader _randomReader;

        [SetUp]
        public void Setup()
        {
            _randomStream = new();
            _randomReader = new(_randomStream);
        }

        [Test]
        public void TestNewDistKeyGenerator()
        {
            var (partPubs, partSec, _) = Generate(_defaultN, _defaultT);

            var longSec = partSec[0];

            var dkg = DistKeyGenerator.CreateDistKeyGenerator(longSec, partPubs, _defaultT);
            Assert.That(dkg, Is.Not.Null);
            Assert.Multiple(() =>
            {
                Assert.That(dkg.Dealer, Is.Not.Null);
                Assert.That(dkg.CanIssue, Is.True);
                Assert.That(dkg.CanReceive, Is.True);
                Assert.That(dkg.NewPresent, Is.True);
                // because we set old = new
                Assert.That(dkg.OldPresent, Is.True);
                Assert.That(dkg.CanReceive, Is.True);
                Assert.That(dkg.IsResharing, Is.False);
            });

            var (sec, _) = KeyPair();
            Assert.Throws<DkgError>(() => DistKeyGenerator.CreateDistKeyGenerator(sec, partPubs, _defaultT));
            IPoint[] empty = [];
            Assert.Throws<DkgError>(() => DistKeyGenerator.CreateDistKeyGenerator(sec, empty, _defaultT));
        }

        [Test]
        public void TestProcessDeal()
        {
            var (_, _, dkgs) = Generate(_defaultN, _defaultT);
            var dkg = dkgs[0];
            var deals = dkg.Deals();     // No exception
            Assert.That(deals, Is.Not.Null);

            var rec = dkgs[1];
            var deal = deals[1];
            Assert.Multiple(() =>
            {
                Assert.That(deal.Index, Is.EqualTo(0));
                Assert.That(rec.Nidx, Is.EqualTo(1));
            });

            // verifier don't find itself
            var goodP = rec.C.NewNodes;
            rec.C.NewNodes = [];
            Assert.Throws<DkgError>(() => rec.ProcessDeal(deal));
            rec.C.NewNodes = goodP;

            // good deal
            var resp = rec.ProcessDeal(deal);
            Assert.That(resp, Is.Not.Null);
            Assert.Multiple(() =>
            {
                Assert.That(resp.VssResponse.Status, Is.EqualTo(ResponseStatus.Approval));
                Assert.That(rec.Verifiers.ContainsKey(deal.Index), Is.True);
                Assert.That(resp.Index, Is.EqualTo(0));
            });

            // duplicate
            rec.ProcessDeal(deal);
            // Assert.Throws<DkgError>(() => rec.ProcessDeal(deal));

            // wrong index
            var goodIdx = deal.Index;
            deal.Index = _defaultN + 1;
            Assert.Throws<DkgError>(() => rec.ProcessDeal(deal));
            deal.Index = goodIdx;

            // wrong deal
            var goodSig = deal.VssDeal.Signature;
            deal.VssDeal.Signature = _randomReader.ReadBytes(goodSig.Length);
            Assert.Throws<DkgError>(() => rec.ProcessDeal(deal));
            deal.VssDeal.Signature = goodSig;
        }

        [Test]
        public void TestProcessResponse()
        {
            // first peer generates wrong deal
            // second peer processes it and returns a complaint
            // first peer process the complaint

            var (_, _, dkgs) = Generate(_defaultN, _defaultT);
            var dkg = dkgs[0];
            var idxRec = 1;
            var rec = dkgs[idxRec];
            var deal = dkg.Dealer.PlaintextDeal(idxRec);

            // give a wrong deal
            var goodSecret = deal.SecShare.V;
            deal.SecShare.V = _g.Scalar().Zero();
            var dd = dkg.Deals();
            var encD = dd[idxRec];
            var resp = rec.ProcessDeal(encD);
            Assert.That(resp.VssResponse.Status, Is.EqualTo(ResponseStatus.Complaint));
            deal.SecShare.V = goodSecret;
            dd = dkg.Deals();
            encD = dd[idxRec];

            // no verifier tied to Response
            var v = dkg.Verifiers[0];
            Assert.That(dkg.Verifiers.ContainsKey(0), Is.True);
            dkg.Verifiers.Remove(0);
            Assert.Throws<DkgError>(() => dkg.ProcessResponse(resp));
            dkg.Verifiers[0] = v;

            // invalid response
            var goodSig = resp.VssResponse.Signature;
            resp.VssResponse.Signature = _randomReader.ReadBytes(goodSig.Length);
            Assert.Throws<DkgError>(() => dkg.ProcessResponse(resp));
            resp.VssResponse.Signature = goodSig;

            // valid complaint from our deal
            Assert.That(dkg.ProcessResponse(resp), Is.Not.Null); // No exception (?)

            // valid complaint from another deal from another peer
            var dkg2 = dkgs[2];
            var deal21 = dkg2.Dealer.PlaintextDeal(1);
            var goodRnd21 = deal21.SecShare.V;
            deal21.SecShare.V = _g.Scalar().Zero();
            var deals2 = dkg2.Deals();

            var resp12 = rec.ProcessDeal(deals2[idxRec]);
            Assert.Multiple(() =>
            {
                Assert.That(resp12.VssResponse.Status, Is.EqualTo(ResponseStatus.Complaint));
                Assert.That(dkg2.Nidx, Is.EqualTo(deals2[idxRec].Index));
                Assert.That(dkg2.Nidx, Is.EqualTo(resp12.Index));
                Assert.That(rec.Verifiers[dkg2.Oidx].Responses()[rec.Nidx].Status, Is.EqualTo(ResponseStatus.Complaint));
            });

            deal21.SecShare.V = goodRnd21;
            deals2 = dkg2.Deals();

            // give it to the first peer
            // process dealer 2's deal
            var r = dkg.ProcessDeal(deals2[0]);
            
            // Justification part:
            // give the complaint to the dealer
            var j = dkg2.ProcessResponse(resp12);
            Assert.That(j, Is.Not.Null);

            // hack because all is local, and resp has been modified locally by dkg2's
            // dealer, the status has became "justified"
            resp12.VssResponse.Status = ResponseStatus.Complaint;
            Assert.DoesNotThrow(() => dkg.ProcessJustification(j));

            // remove verifiers
            v = dkg.Verifiers[j.Index];
            dkg.Verifiers.Remove(j.Index);
            Assert.Throws<DkgError>(() => dkg.ProcessJustification(j));
            dkg.Verifiers[j.Index] = v;
        }


        [Test]
        public void TestDistKeyShare()
        {
            var (_, _, dkgs) = Generate(_defaultN, _defaultT);
            FullExchange(dkgs, true);

            foreach (var dkg in dkgs)
            {
                Assert.That(dkg.Certified(), Is.True);
            }
            // verify integrity of shares etc
            var dkss = new DistKeyShare[_defaultN];
            PriPoly? poly = null;
            for (var i = 0; i < dkgs.Length; i++)
            {
                var dkg = dkgs[i];
                var dks = dkg.DistKeyShare();
                Assert.That(dks, Is.Not.Null);
                Assert.That(dks.PrivatePoly, Is.Not.Null);
                dkss[i] = dks;
                Assert.That(dks.Share.I, Is.EqualTo(dkg.Nidx));

                var pripoly = new PriPoly(_g, dks.PrivatePoly);
                if (poly == null)
                {
                    poly = pripoly;
                    continue;
                }
                poly = poly.Add(pripoly);
            }

            var shares = new PriShare[_defaultN];
            for (var i = 0; i < dkss.Length; i++)
            {
                var dks = dkss[i];
                Assert.That(dks, Is.EqualTo(dkss[0]), $"dist key share not equal {dks.Share.I} vs 0");
                shares[i] = dks.Share;
            }

            var secret = PriPoly.RecoverSecret(_g, shares, _defaultN, _defaultN);
            Assert.That(secret, Is.Not.Null);

            var secretCoeffs = poly.Coeffs;
            Assert.That(secretCoeffs[0], Is.EqualTo(secret));

            var commitSecret = _g.Point().Base().Mul(secret);
            Assert.That(commitSecret, Is.EqualTo(dkss[0].Public()));
        }

        // TestThreshold tests the "threshold dkg" where only a subset of nodes succeed at the DKG
        [Test]
        public void TestThreshold()
        {
            var n = 7;
            // should succeed with only this number of nodes
            var newTotal = VssTools.MinimumT(n);

            var dkgs = new DistKeyGenerator[n];
            var privates = new IScalar[n];
            var publics = new IPoint[n];
            for (var i = 0; i < n; i++)
            {
                var (priv, pub) = KeyPair();
                privates[i] = priv;
                publics[i] = pub;
            }

            for (var i = 0; i < n; i++)
            {
                var dkg = DistKeyGenerator.CreateDistKeyGenerator(privates[i], publics, newTotal);
                dkgs[i] = dkg;
            }

            // only take a threshold of them
            var thrDKGs = new Dictionary<int, DistKeyGenerator>();
            var alreadyTaken = new Dictionary<int, bool>();
            while (thrDKGs.Count < newTotal)
            {
                var idx = new Random().Next(_defaultN);
                if (alreadyTaken.ContainsKey(idx))
                {
                    continue;
                }
                alreadyTaken[idx] = true;
                var dkg = dkgs[idx];
                thrDKGs[dkg.Nidx] = dkg;
            }

            // full secret sharing exchange
            // 1. broadcast deals
            var resps = new List<DistResponse>();
            foreach (var dkg in thrDKGs.Values)
            {
                var deals = dkg.Deals();
                foreach (var kvp in deals)
                {
                    // give the deal anyway - simpler
                    if (!thrDKGs.TryGetValue(kvp.Key, out var recipient))
                    {
                        // one of the "offline" dkg
                        continue;
                    }
                    var resp = recipient.ProcessDeal(kvp.Value);
                    Assert.That(resp.VssResponse.Status, Is.EqualTo(ResponseStatus.Approval));
                    resps.Add(resp);
                }
            }

            // 2. Broadcast responses
            foreach (var resp in resps)
            {
                foreach (var dkg in thrDKGs.Values)
                {
                    if (resp.VssResponse.Index == dkg.Nidx)
                    {
                        // skip the responses this dkg sent out
                        continue;
                    }
                    Assert.DoesNotThrow(() => dkg.ProcessResponse(resp));
                }
            }

            // 3. make sure nobody has a QUAL set
            foreach (var dkg in thrDKGs.Values)
            {
                Assert.That(dkg.Certified(), Is.False);
                Assert.That(dkg.QUAL().Count, Is.EqualTo(0));
                foreach (var dkg2 in thrDKGs.Values)
                {
                    Assert.That(dkg.IsInQUAL(dkg2.Nidx), Is.False);
                }
            }

            foreach (var dkg in thrDKGs.Values)
            {
                foreach (var (i, v) in dkg.Verifiers)
                {
                    var app = v.Responses().Count(r => r.Value.Status == ResponseStatus.Approval);
                    if (alreadyTaken.ContainsKey(i))
                    {
                        Assert.That(app, Is.EqualTo(alreadyTaken.Count));
                    }
                    else
                    {
                        Assert.That(app, Is.EqualTo(0));
                    }
                }
                dkg.SetTimeout();
            }

            foreach (var dkg in thrDKGs.Values)
            {
                Assert.That(dkg.QUAL(), Has.Count.EqualTo(newTotal));
                Assert.That(dkg.ThresholdCertified(), Is.True);
                Assert.That(dkg.Certified(), Is.False);
                var qualShares = dkg.QualifiedShares();
                foreach (var dkg2 in thrDKGs.Values)
                {
                    Assert.That(qualShares, Does.Contain(dkg2.Nidx));
                }
                Assert.DoesNotThrow(() => dkg.DistKeyShare());
                foreach (var dkg2 in thrDKGs.Values)
                {
                    Assert.That(dkg.IsInQUAL(dkg2.Nidx), Is.True);
                }
            }
        }

        // Test Resharing to a group with one mode node BUT only a threshold of dealers
        // are present during the resharing.
        //[Test]
        public void TestDKGResharingThreshold()
        {
            var n = 7;
            var oldT = VssTools.MinimumT(n);
            var (publics, _, dkgs) = Generate(n, oldT);
            FullExchange(dkgs, true);

            var newN = dkgs.Length + 1;
            var newT = VssTools.MinimumT(newN);
            var shares = new DistKeyShare[dkgs.Length];
            var sshares = new PriShare[dkgs.Length];
            for (var i = 0; i < dkgs.Length; i++)
            {
                var dkg = dkgs[i];
                var share = dkg.DistKeyShare();
                shares[i] = share;
                sshares[i] = shares[i].Share;
            }

            var newPubs = new IPoint[newN];
            for (var i = 0; i < dkgs.Length; i++)
            {
                newPubs[i] = dkgs[i].Pub;
            }
            var (newPriv, newPub) = KeyPair();
            newPubs[dkgs.Length] = newPub;
            var newDkgs = new DistKeyGenerator[newN];
            for (var i = 0; i < dkgs.Length; i++)
            {
                var c = new Config(dkgs[i].C.LongTermKey, newPubs, newT)
                {
                    OldNodes = publics,
                    Share = shares[i],
                    OldThreshold = oldT
                };
                newDkgs[i] = new DistKeyGenerator(c);
            }
            newDkgs[dkgs.Length] = new DistKeyGenerator(
                new Config(newPriv, newPubs, newT)
                {
                    OldNodes = publics,
                    NewNodes = newPubs,
                    PublicCoeffs = shares[0].Commits,
                    OldThreshold = oldT
                });

            var selectedDkgs = new List<DistKeyGenerator>();
            var selected = new Dictionary<string, bool>();
            // add the new node
            selectedDkgs.Add(newDkgs[dkgs.Length]);
            selected[selectedDkgs[0].LongTermKey.ToString()!] = true;
            // select a subset of the new group
            while (selected.Count < newT + 1)
            {
                int idx = _randomReader.ReadInt32() % (newDkgs.Length - 1);
                idx = idx < 0 ? -idx : idx;
                var str = newDkgs[idx].LongTermKey.ToString()!;
                if (selected.ContainsKey(str))
                {
                    continue;
                }
                selected[str] = true;
                selectedDkgs.Add(newDkgs[idx]);
            }

            var deals = new List<Dictionary<int, DistDeal>>();
            foreach (var dkg in selectedDkgs)
            {
                if (!dkg.OldPresent)
                {
                    continue;
                }
                var localDeals = dkg.Deals();
                deals.Add(localDeals);
            }

            var resps = new Dictionary<int, List<DistResponse>>();
            for (var i = 0; i < deals.Count; i++)
            {
                var localDeals = deals[i];
                foreach (var d in localDeals)
                {
                    foreach (var dkg in selectedDkgs)
                    {
                        if (dkg.NewPresent && dkg.Nidx == d.Key)
                        {
                            var resp = dkg.ProcessDeal(d.Value);
                            Assert.That(resp, Is.Not.Null);
                            Assert.That(resp.VssResponse.Status, Is.EqualTo(ResponseStatus.Approval));
                            if (!resps.ContainsKey(i))
                            {
                                resps[i] = [];
                            }
                            resps[i].Add(resp);
                        }
                    }
                }
            }

            foreach (var dealResponses in resps.Values)
            {
                foreach (var resp in dealResponses)
                {
                    foreach (var dkg in selectedDkgs)
                    {
                        // Ignore messages from ourselves
                        if (resp.VssResponse.Index == dkg.Nidx)
                        {
                            continue;
                        }
                        Assert.DoesNotThrow(() => dkg.ProcessResponse(resp));
                    }
                }
            }

            foreach (var dkg in selectedDkgs)
            {
                dkg.SetTimeout();
            }

            var dkss = new List<DistKeyShare>();
            var newShares = new List<PriShare>();
            foreach (var dkg in selectedDkgs)
            {
                if (!dkg.NewPresent)
                {
                    continue;
                }
                Assert.IsFalse(dkg.Certified());
                Assert.That(dkg.ThresholdCertified(), Is.True);
                var dks = dkg.DistKeyShare();
                dkss.Add(dks);
                newShares.Add(dks.Share);
                var qualShares = dkg.QualifiedShares();
                foreach (var dkg2 in selectedDkgs)
                {
                    if (!dkg.NewPresent)
                    {
                        continue;
                    }
                    Assert.Contains(dkg2.Nidx, qualShares);
                }
            }

            // check
            // 1. shares are different between the two rounds
            // 2. shares reconstruct to the same secret
            // 3. public polynomial is different but for the first coefficient /public
            // key/

            foreach (var newDks in dkss)
            {
                foreach (var oldDks in shares)
                {
                    Assert.That(oldDks.Share.V.ToString(), Is.Not.EqualTo(newDks.Share.V.ToString()));
                }
            }
            // 2.
            var oldSecret = PriPoly.RecoverSecret(_g, sshares, oldT, n);
            var newSecret = PriPoly.RecoverSecret(_g, [.. newShares], newT, newN);
            Assert.That(newSecret, Is.EqualTo(oldSecret));
        }

        // Test resharing of a DKG to the same set of nodes
        //[Test]
        public void TestDKGResharing()
        {
            var oldT = VssTools.MinimumT(_defaultN);
            var (publics, secrets, dkgs) = Generate(_defaultN, oldT);
            FullExchange(dkgs, true);

            var shares = new DistKeyShare[dkgs.Length];
            var sshares = new PriShare[dkgs.Length];
            for (var i = 0; i < dkgs.Length; i++)
            {
                var share = dkgs[i].DistKeyShare();
                shares[i] = share;
                sshares[i] = shares[i].Share;
            }
            // start resharing within the same group
            var newDkgs = new DistKeyGenerator[dkgs.Length];
            for (var i = 0; i < dkgs.Length; i++)
            {
                var c = new Config(secrets[i], publics, oldT)
                {
                    OldNodes = publics,
                    Share = shares[i],
                    OldThreshold = oldT
                };
                newDkgs[i] = new DistKeyGenerator(c);
            }
            FullExchange(newDkgs, true);
            var newShares = new DistKeyShare[dkgs.Length];
            var newSShares = new PriShare[dkgs.Length];
            for (var i = 0; i < newDkgs.Length; i++)
            {
                var dks = newDkgs[i].DistKeyShare();
                newShares[i] = dks;
                newSShares[i] = newShares[i].Share;
            }
            // check
            // 1. shares are different between the two rounds
            // 2. shares reconstruct to the same secret
            // 3. public polynomial is different but for the first coefficient /public
            // key/
            // 1.
            for (var i = 0; i < dkgs.Length; i++)
            {
                Assert.That(newShares[i].Share.V, Is.Not.EqualTo(shares[i].Share.V));
            }
            var thr = VssTools.MinimumT(_defaultN);
            // 2.
            var oldSecret = PriPoly.RecoverSecret(_g, sshares, thr, _defaultN);
            var newSecret = PriPoly.RecoverSecret(_g, newSShares, thr, _defaultN);
            Assert.That(newSecret, Is.EqualTo(oldSecret));
        }


        private (IScalar prv, IPoint pub) KeyPair()
        {
            var prv = _g.Scalar();
            var pub = _g.Point().Base().Mul(prv);
            return (prv, pub);
        }

        private (IPoint[] partPubs, IScalar[], DistKeyGenerator[] dkgs) Generate(int n, int t)
        {
            var partPubs = new IPoint[n];
            var partSec = new IScalar[n];
            for (int i = 0; i < n; i++)
            {
                var (sec, pub) = KeyPair();
                partPubs[i] = pub;
                partSec[i] = sec;
            }
            DistKeyGenerator[] dkgs = new DistKeyGenerator[n];
            for (int i = 0; i < n; i++)
            {
                var dkg = DistKeyGenerator.CreateDistKeyGenerator(partSec[i], partPubs, t);
                dkgs[i] = dkg;
            }
            return (partPubs, partSec, dkgs);
        }

        private void FullExchange(DistKeyGenerator[] dkgs, bool checkQUAL)
        {
            // full secret sharing exchange
            // 1. broadcast deals
            var n = dkgs.Length;
            var resps = new List<DistResponse>();
            foreach (var dkg in dkgs)
            {
                var deals = dkg.Deals();
                foreach (var kvp in deals)
                {
                    var d = kvp.Value;
                    var resp = dkgs[kvp.Key].ProcessDeal(d);
                    Assert.That(resp, Is.Not.Null);
                    Assert.That(resp.VssResponse.Status, Is.EqualTo(ResponseStatus.Approval));
                    resps.Add(resp);
                }
            }
            // 2. Broadcast responses
            foreach (var resp in resps)
            {
                foreach (var dkg in dkgs)
                {
                    // Ignore messages about ourselves
                    if (resp.VssResponse.Index == dkg.Nidx)
                    {
                        continue;
                    }
                    Assert.DoesNotThrow(() => dkg.ProcessResponse(resp));
                }
            }

            if (checkQUAL)
            {
                // 3. make sure everyone has the same QUAL set
                foreach (var dkg in dkgs)
                {
                    foreach (var dkg2 in dkgs)
                    {
                        Assert.That(dkg.IsInQUAL(dkg2.Nidx), Is.True);
                    }
                }
            }
        }
    }
}