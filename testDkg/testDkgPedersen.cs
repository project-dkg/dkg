
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
using dkg.group;
using dkg.poly;
using Google.Protobuf.Collections;
using Newtonsoft.Json;
using Org.BouncyCastle.Pqc.Crypto.Lms;
using Org.BouncyCastle.Tls.Crypto;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Net;
using System.Runtime.Intrinsics.X86;
using static NUnit.Framework.Constraints.Tolerance;

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
        public void TestDistKeySharing()
        {
            var (_, _, dkgs) = Generate(_defaultN, _defaultT);
            Assert.DoesNotThrow(()=>FullExchange(dkgs, true));

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
        public void TestDistKeySharingThreshold()
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
        [Test]
        public void TestDistKeyResharingThreshold()
        {
            var n = 7;
            var oldT = VssTools.MinimumT(n);
            var (publics, _, dkgs) = Generate(n, oldT);
            Assert.DoesNotThrow(()=>FullExchange(dkgs, true));

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
                var c = new Config()
                {
                    LongTermKey = dkgs[i].C.LongTermKey,
                    OldNodes = publics,
                    NewNodes = newPubs,
                    Share = shares[i],
                    Threshold = newT,
                    OldThreshold = oldT
                };
		

                newDkgs[i] = new DistKeyGenerator(c);
            }
            newDkgs[dkgs.Length] = new DistKeyGenerator(
                new Config()
                {
                    LongTermKey = newPriv,
                    OldNodes = publics,
                    NewNodes = newPubs,
                    PublicCoeffs = shares[0].Commits,
                    Threshold = newT,
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
                Assert.That(dkg.Certified(), Is.False);
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
        [Test]
        public void TestDistKeyResharing()
        {
            var oldT = VssTools.MinimumT(_defaultN);
            var (publics, secrets, dkgs) = Generate(_defaultN, oldT);
            Assert.DoesNotThrow(()=>FullExchange(dkgs, true));

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
                var c = new Config()
                {
                    LongTermKey = secrets[i], 
                    NewNodes = publics,
                    OldNodes = publics,
                    Share = shares[i],
                    OldThreshold = oldT
                };
                newDkgs[i] = new DistKeyGenerator(c);
            }
            Assert.DoesNotThrow(()=>FullExchange(newDkgs, true));
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

        // Test resharing functionality with one node less
        [Test]
        public void TestDistKeyResharingRemoveNode()
        {
            int oldT = VssTools.MinimumT(_defaultN);
            var (publics, secrets, dkgs) = Generate(_defaultN, oldT);
            Assert.DoesNotThrow(()=>FullExchange(dkgs, true));

            int newN = publics.Length - 1;
            var shares = new DistKeyShare[dkgs.Length];
            var sshares = new PriShare[dkgs.Length];
            for (int i = 0; i < dkgs.Length; i++)
            {
                try
                {
                    shares[i] = dkgs[i].DistKeyShare();
                    sshares[i] = shares[i].Share;
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            // start resharing within the same group
            var newDkgs = new DistKeyGenerator[dkgs.Length];
            for (int i = 0; i < dkgs.Length; i++)
            {
                var c = new Config
                {
                    LongTermKey = secrets[i],
                    OldNodes = publics,
                    NewNodes = publics.Take(newN).ToArray(),
                    Share = shares[i],
                    OldThreshold = oldT,
                };
                try
                {
                    newDkgs[i] = new DistKeyGenerator(c);
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            Assert.DoesNotThrow(()=>FullExchange(newDkgs, false));
            var newShares = new DistKeyShare[dkgs.Length];
            var newSShares = new PriShare[dkgs.Length - 1];
            for (int i = 0; i < newN; i++)
            {
                try
                {
                    newShares[i] = newDkgs[i].DistKeyShare();
                    newSShares[i] = newShares[i].Share;
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            // check
            // 1. shares are different between the two rounds
            // 2. shares reconstruct to the same secret
            // 3. public polynomial is different but for the first coefficient /public
            // key/

            // 1.
            for (int i = 0; i < newN; i++)
            {
                Assert.That(newShares[i].Share.V, Is.Not.EqualTo(shares[i].Share.V));
            }
            int thr = VssTools.MinimumT(_defaultN);
            // 2.
            try
            {
                var oldSecret = PriPoly.RecoverSecret(_g, sshares.Take(newN).ToArray(), thr, newN);
                var newSecret = PriPoly.RecoverSecret(_g, newSShares, thr, newN);
                Assert.That(newSecret, Is.EqualTo(oldSecret));
            }
            catch (DkgError ex)
            {
                Assert.Fail(ex.Message);
            }
        }

        // Test to reshare to a different set of nodes with only a threshold of the old
        // nodes present
        [Test]
        public void TestDistKeyResharingNewNodesThreshold()
        {
            int oldN = _defaultN;
            int oldT = VssTools.MinimumT(oldN);
            var (oldPubs, oldPrivs, dkgs) = Generate(oldN, oldT);
            Assert.DoesNotThrow(()=>FullExchange(dkgs, true));

            var shares = new DistKeyShare[dkgs.Length];
            var sshares = new PriShare[dkgs.Length];
            for (int i = 0; i < dkgs.Length; i++)
            {
                try
                {
                    shares[i] = dkgs[i].DistKeyShare();
                    sshares[i] = shares[i].Share;
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            // start resharing to a different group
            int newN = oldN + 3;
            int newT = oldT + 2;
            var newPrivs = new IScalar[newN];
            var newPubs = new IPoint[newN];
            for (int i = 0; i < newN; i++)
            {
                (newPrivs[i], newPubs[i]) = KeyPair();
            }

            // creating the old dkgs and new dkgs
            var oldDkgs = new DistKeyGenerator[oldN];
            var newDkgs = new DistKeyGenerator[newN];
            for (int i = 0; i < oldN; i++)
            {
                var c = new Config
                {
                    LongTermKey = oldPrivs[i],
                    OldNodes = oldPubs,
                    NewNodes = newPubs,
                    Share = shares[i],
                    Threshold = newT,
                    OldThreshold = oldT,
                };
                try
                {
                    oldDkgs[i] = new DistKeyGenerator(c);
                    Assert.Multiple(() =>
                    {
                        Assert.That(oldDkgs[i].CanReceive, Is.False);
                        Assert.That(oldDkgs[i].CanIssue, Is.True);
                        Assert.That(oldDkgs[i].IsResharing, Is.True);
                        Assert.That(oldDkgs[i].NewPresent, Is.False);
                        Assert.That(oldDkgs[i].Oidx, Is.EqualTo(i));
                    });
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            for (int i = 0; i < newN; i++)
            {
                var c = new Config
                {
                    LongTermKey = newPrivs[i],
                    OldNodes = oldPubs,
                    NewNodes = newPubs,
                    PublicCoeffs = shares[0].Commits,
                    Threshold = newT,
                    OldThreshold = oldT,
                };
                try
                {
                    newDkgs[i] = new DistKeyGenerator(c);
                    Assert.Multiple(() =>
                    {
                        Assert.That(newDkgs[i].CanReceive, Is.True);
                        Assert.That(newDkgs[i].CanIssue, Is.False);
                        Assert.That(newDkgs[i].IsResharing, Is.True);
                        Assert.That(newDkgs[i].NewPresent, Is.True);
                        Assert.That(newDkgs[i].Nidx, Is.EqualTo(i));
                    });
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            int alive = oldT;
            var oldSelected = new List<DistKeyGenerator>();
            var selected = new Dictionary<string, bool>();
            while (selected.Count < alive)
            {
                int i = new Random().Next(oldDkgs.Length);
                string str = oldDkgs[i].LongTermKey.ToString();
                if (selected.ContainsKey(str))
                {
                    continue;
                }
                selected[str] = true;
                oldSelected.Add(oldDkgs[i]);
            }

            // 1. broadcast deals
            var deals = new List<Dictionary<int, DistDeal>>();
            foreach (var dkg in oldSelected)
            {
                try
                {
                    var localDeals = dkg.Deals();
                    deals.Add(localDeals);
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            var resps = new Dictionary<int, List<DistResponse>>();
            for (int i = 0; i < deals.Count; i++)
            {
                foreach (var d in deals[i])
                {
                    var dkg = newDkgs[d.Key];
                    try
                    {
                        var resp = dkg.ProcessDeal(d.Value);
                        Assert.That(resp.VssResponse.Status, Is.EqualTo(ResponseStatus.Approval));
                        if (!resps.ContainsKey(i))
                        {
                            resps[i] = [];
                        }
                        resps[i].Add(resp);
                    }
                    catch (DkgError ex)
                    {
                        Assert.Fail(ex.Message);
                    }
                }
            }

            // 2. Broadcast responses
            foreach (var dealResponses in resps.Values)
            {
                foreach (var resp in dealResponses)
                {
                    // dispatch to old selected dkgs
                    foreach (var dkg in oldSelected)
                    {
                        // Ignore messages from ourselves
                        if (resp.Index == dkg.Nidx)
                        {
                            continue;
                        }
                        try
                        {
                            // Console.WriteLine($"old dkg at (oidx {dkg.Oidx}, nidx {dkg.Nidx}) has received response from idx {resp.VssResponse.Index} for dealer idx {resp.Index}");
                            var j = dkg.ProcessResponse(resp);
                            Assert.That(j, Is.Null);
                        }
                        catch (DkgError ex)
                        {
                            Assert.Fail(ex.Message);
                        }
                    }
                    // dispatch to the new dkgs
                    foreach (var dkg in newDkgs)
                    {
                        // Ignore messages from ourselves
                        if (resp.VssResponse.Index == dkg.Nidx)
                        {
                            continue;
                        }
                        try
                        {
                            // Console.WriteLine($"new dkg at (oidx {dkg.Oidx}, nidx {dkg.Nidx}) has received response from idx {resp.VssResponse.Index} for dealer idx {resp.Index}");
                            var j = dkg.ProcessResponse(resp);
                            Assert.That(j, Is.Null);
                        }
                        catch (DkgError ex)
                        {
                            Assert.Fail(ex.Message);
                        }
                    }
                }
            }

            foreach (var dkg in newDkgs)
            {
                foreach (var oldDkg in oldSelected)
                {
                    int idx = oldDkg.Oidx;
                    Assert.That(dkg.Verifiers[idx].DealCertified(), Is.True);
                }
            }

            // 3. make sure everyone has the same QUAL set
            foreach (var dkg in newDkgs)
            {
                Assert.That(dkg.QUAL().Count, Is.EqualTo(alive));
                foreach (var dkg2 in oldSelected)
                {
                    Assert.That(dkg.IsInQUAL(dkg2.Oidx), Is.True);
                }
            }

            var newShares = new DistKeyShare[newN];
            var newSShares = new PriShare[newN];
            for (int i = 0; i < newDkgs.Length; i++)
            {
                try
                {
                    newShares[i] = newDkgs[i].DistKeyShare();
                    newSShares[i] = newShares[i].Share;
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            // check shares reconstruct to the same secret
            try
            {
                var oldSecret = PriPoly.RecoverSecret(_g, sshares, oldT, oldN);
                var newSecret = PriPoly.RecoverSecret(_g, newSShares, newT, newN);
                Assert.That(newSecret, Is.EqualTo(oldSecret));
            }
            catch (DkgError ex)
            {
                Assert.Fail(ex.Message);
            }
        }

        // Test resharing to a different set of nodes with two common.
        [Test]
        public void TestDistKeyResharingNewNodes()
        {
            var (oldPubs, oldPrivs, dkgs) = Generate(_defaultN, VssTools.MinimumT(_defaultN));
            Assert.DoesNotThrow(()=>FullExchange(dkgs, true));

            var shares = new DistKeyShare[dkgs.Length];
            var sshares = new PriShare[dkgs.Length];
            for (int i = 0; i < dkgs.Length; i++)
            {
                try
                {
                    shares[i] = dkgs[i].DistKeyShare();
                    sshares[i] = shares[i].Share;
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            // start resharing to a different group
            int oldN = _defaultN;
            int oldT = shares[0].Commits.Length;
            int newN = oldN + 1;
            int newT = oldT + 1;
            var newPrivs = new IScalar[newN];
            var newPubs = new IPoint[newN];

            // new[0], new[1] = old[-1], old[-2]
            newPrivs[0] = oldPrivs[oldN - 1];
            newPubs[0] = oldPubs[oldN - 1];
            newPrivs[1] = oldPrivs[oldN - 2];
            newPubs[1] = oldPubs[oldN - 2];

            for (int i = 2; i < newN; i++)
            {
                (newPrivs[i], newPubs[i]) = KeyPair();
            }

            // creating the old dkgs
            var oldDkgs = new DistKeyGenerator[oldN];
            for (int i = 0; i < oldN; i++)
            {
                var c = new Config
                {
                    LongTermKey = oldPrivs[i],
                    OldNodes = oldPubs,
                    NewNodes = newPubs,
                    Share = shares[i],
                    Threshold = newT,
                    OldThreshold = oldT,
                };
                try
                {
                    oldDkgs[i] = new DistKeyGenerator(c);
                    if (i >= oldN - 2)
                    {
                        Assert.Multiple(() =>
                        {
                            Assert.That(oldDkgs[i].CanReceive, Is.True);
                            Assert.That(oldDkgs[i].CanIssue, Is.True);
                            Assert.That(oldDkgs[i].IsResharing, Is.True);
                            Assert.That(oldDkgs[i].NewPresent, Is.True);
                            Assert.That(oldDkgs[i].Oidx, Is.EqualTo(i));
                            Assert.That(oldDkgs[i].Nidx, Is.EqualTo(oldN - i - 1));
                        });
                        continue;
                    }

                   Assert.Multiple(() =>
                   {
                        Assert.That(oldDkgs[i].CanReceive, Is.False);
                        Assert.That(oldDkgs[i].CanIssue, Is.True);
                        Assert.That(oldDkgs[i].IsResharing, Is.True);
                        Assert.That(oldDkgs[i].NewPresent, Is.False);
                        Assert.That(oldDkgs[i].Nidx, Is.EqualTo(0)); // default for nidx
                        Assert.That(oldDkgs[i].Oidx, Is.EqualTo(i));
                   });
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            // creating the new dkg
            var newDkgs = new DistKeyGenerator[newN];
            newDkgs[0] = oldDkgs[oldN - 1]; // the first one is the last old one
            newDkgs[1] = oldDkgs[oldN - 2]; // the second one is the before-last old one

            for (int i = 2; i < newN; i++)
            {
                var c = new Config
                {
                    LongTermKey = newPrivs[i],
                    OldNodes = oldPubs,
                    NewNodes = newPubs,
                    PublicCoeffs = shares[0].Commits,
                    Threshold = newT,
                    OldThreshold = oldT,
                };
                try
                {
                    newDkgs[i] = new DistKeyGenerator(c);
                    Assert.Multiple(() =>
                    {
                        Assert.That(newDkgs[i].CanReceive, Is.True);
                        Assert.That(newDkgs[i].CanIssue, Is.False);
                        Assert.That(newDkgs[i].IsResharing, Is.True);
                        Assert.That(newDkgs[i].NewPresent, Is.True);
                        Assert.That(newDkgs[i].Nidx, Is.EqualTo(i));
                        Assert.That(newDkgs[i].Verifiers.Count, Is.EqualTo(oldN));
                    });
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            // full secret sharing exchange
            // 1. broadcast deals
            var deals = new Dictionary<int, DistDeal>[oldDkgs.Length];
            for (int i = 0; i < oldDkgs.Length; i++)
            {
                try
                {
                    var localDeals = oldDkgs[i].Deals();
                    Assert.That(localDeals, Has.Count.EqualTo(newN));
                    deals[i] = localDeals;
                    if (oldDkgs[i].CanReceive && oldDkgs[i].Nidx <= 1)
                    {
                        Assert.That(oldDkgs[i].Verifiers[oldDkgs[i].Oidx].Responses(), Is.Empty);
                    }
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            // the index key indicates the dealer index for which the responses are for
            var resps = new Dictionary<int, List<DistResponse>>();
            for (int i = 0; i < deals.Length; i++)
            {
                foreach (var d in deals[i])
                {
                    var dkg = newDkgs[d.Key];
                    try
                    {
                        var resp = dkg.ProcessDeal(d.Value);
                        Assert.That(resp.VssResponse.Status, Is.EqualTo(ResponseStatus.Approval));
                        if (!resps.ContainsKey(i))
                        {
                            resps[i] = new List<DistResponse>();
                        }
                        resps[i].Add(resp);
                    }
                    catch (DkgError ex)
                    {
                        Assert.Fail(ex.Message);
                    }
                }
            }

            // all new dkgs should have the same length of verifiers map
            foreach (var dkg in newDkgs)
            {
                // one deal per old participants
                Assert.That(dkg.Verifiers, Has.Count.EqualTo(oldN));
            }

            // 2. Broadcast responses
            foreach (var dealResponses in resps.Values)
            {
                foreach (var resp in dealResponses)
                {
                    // the two last ones will be processed while doing this step on the
                    // newDkgs, since they are in the new set.
                    for (int i = 0; i < oldN - 2; i++)
                    {
                        try
                        {
                            var j = oldDkgs[i].ProcessResponse(resp);      // inconsistent sessionid in response
                            Assert.That(j, Is.Null);
                        }
                        catch (DkgError ex)
                        {
                            Assert.Fail(ex.Message);
                        }
                    }

                    foreach (var dkg in newDkgs)
                    {
                        // Ignore messages from ourselves
                        if (resp.VssResponse.Index == dkg.Nidx)
                        {
                            continue;
                        }
                        try
                        {
                            var j = dkg.ProcessResponse(resp);
                            Assert.That(j, Is.Null);
                        }
                        catch (DkgError ex)
                        {
                            Assert.Fail(ex.Message);
                        }
                    }
                }
            }

            foreach (var dkg in newDkgs)
            {
                for (int i = 0; i < oldN; i++)
                {
                    Assert.That(dkg.Verifiers[i].DealCertified(), Is.True);
                }
            }

            // 3. make sure everyone has the same QUAL set
            foreach (var dkg in newDkgs)
            {
                foreach (var dkg2 in oldDkgs)
                {
                    Assert.That(dkg.IsInQUAL(dkg2.Oidx), Is.True);
                }
            }

            // make sure the new dkg members can certify
            foreach (var dkg in newDkgs)
            {
                Assert.That(dkg.Certified(), Is.True);
            }

            // make sure the old dkg members can certify
            foreach (var dkg in oldDkgs)
            {
                Assert.That(dkg.Certified(), Is.True);
            }

            var newShares = new DistKeyShare[newN];
            var newSShares = new PriShare[newN];
            for (int i = 0; i < newDkgs.Length; i++)
            {
                try
                {
                    newShares[i] = newDkgs[i].DistKeyShare();
                    newSShares[i] = newShares[i].Share;
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            // check shares reconstruct to the same secret
            try
            {
                var oldSecret = PriPoly.RecoverSecret(_g, sshares, oldT, oldN);
                var newSecret = PriPoly.RecoverSecret(_g, newSShares, newT, newN);
                Assert.That(newSecret, Is.EqualTo(oldSecret));
            }
            catch (DkgError ex)
            {
                Assert.Fail(ex.Message);
            }
        }

        [Test]
        public void TestDistKeyResharingPartialNewNodes()
        {
            var (oldPubs, oldPrivs, dkgs) = Generate(_defaultN, VssTools.MinimumT(_defaultN));
            Assert.DoesNotThrow(() => FullExchange(dkgs, true));

            var shares = new DistKeyShare[dkgs.Length];
            var sshares = new PriShare[dkgs.Length];

            for (var i = 0; i < dkgs.Length; i++)
            {
                try
                {
                    shares[i] = dkgs[i].DistKeyShare();
                    sshares[i] = shares[i].Share;
                }
                catch (DkgError ex)
                {
                    Assert.Fail(ex.Message);
                }
            }

            // start resharing to a different group
            var oldN = _defaultN;
            var oldT = shares[0].Commits.Length;
            var newN = oldN + 1;
            var newT = oldT + 1;
            var total = oldN + 2;
            var newOffset = oldN - 1; // idx at which a new key is added to the group

            var newPrivs = new List<IScalar>(oldPrivs.Skip(1));
            var newPubs = new List<IPoint>(oldPubs.Skip(1));
            // add two new nodes
            var (priv1, pub1) = KeyPair();
            var (priv2, pub2) = KeyPair();
            newPrivs.AddRange(new[] { priv1, priv2 });
            newPubs.AddRange(new[] { pub1, pub2 });

            // creating all dkgs
            var totalDkgs = new DistKeyGenerator[total];
            for (var i = 0; i < oldN; i++)
            {
                var c = new Config
                {
                    LongTermKey = oldPrivs[i],
                    OldNodes = oldPubs,
                    NewNodes = newPubs.ToArray(),
                    Share = shares[i],
                    Threshold = newT,
                    OldThreshold = oldT,
                };
                totalDkgs[i] = new DistKeyGenerator(c);
                if (i >= 1)
                {
                    Assert.Multiple(() =>
                    {
                        Assert.That(totalDkgs[i].CanReceive, Is.True);
                        Assert.That(totalDkgs[i].CanIssue, Is.True);
                        Assert.That(totalDkgs[i].IsResharing, Is.True);
                        Assert.That(totalDkgs[i].NewPresent, Is.True);
                        Assert.That(totalDkgs[i].Oidx, Is.EqualTo(i));
                        Assert.That(totalDkgs[i].Nidx, Is.EqualTo(i - 1));
                    });
                    continue;
                }

                Assert.Multiple(() =>
                {
                    Assert.That(totalDkgs[i].CanReceive, Is.False);
                    Assert.That(totalDkgs[i].CanIssue, Is.True);
                    Assert.That(totalDkgs[i].IsResharing, Is.True);
                    Assert.That(totalDkgs[i].NewPresent, Is.False);
                    Assert.That(totalDkgs[i].Oidx, Is.EqualTo(i));
                });
            }

            // the first one is the last old one
            for (var i = oldN; i < total; i++)
            {
                var newIdx = i - oldN + newOffset;
                var c = new Config
                {
                    LongTermKey = newPrivs[newIdx],
                    OldNodes = oldPubs,
                    NewNodes = newPubs.ToArray(),
                    PublicCoeffs = shares[0].Commits,
                    Threshold = newT,
                    OldThreshold = oldT,
                };
                totalDkgs[i] = new DistKeyGenerator(c);
                Assert.Multiple(() =>
                {
                    Assert.That(totalDkgs[i].CanReceive, Is.True);
                    Assert.That(totalDkgs[i].CanIssue, Is.False);
                    Assert.That(totalDkgs[i].IsResharing, Is.True);
                    Assert.That(totalDkgs[i].NewPresent, Is.True);
                    Assert.That(totalDkgs[i].Nidx, Is.EqualTo(newIdx));
                });
            }

            var newDkgs = totalDkgs.Skip(1).ToArray();
            var oldDkgs = totalDkgs.Take(oldN).ToArray();
            Assert.Multiple(() =>
            {
                Assert.That(oldDkgs, Has.Length.EqualTo(oldN));
                Assert.That(newDkgs, Has.Length.EqualTo(newN));
            });

            // full secret sharing exchange
            // 1. broadcast deals
            List<Dictionary<int, DistDeal>> deals = new(newN * newN);

            foreach (var dkg in oldDkgs)
            {
                var localDeals = dkg.Deals();
                Assert.That(localDeals, Is.Not.Null);
                deals.Add(localDeals);

                dkg.Verifiers.TryGetValue(dkg.Oidx, out Verifier? v);

                if (dkg.CanReceive && dkg.NewPresent)
                {
                    Assert.That(v, Is.Not.Null);
                    // staying nodes don't process their responses locally because they
                    // broadcast them for the old comities to receive the responses.
                    int lenResponses = v.Aggregator.Responses.Count;
                    Assert.That(lenResponses, Is.EqualTo(0));
                }
                else
                {
                    Assert.That(v, Is.Null);
                }
            }

            // the index key indicates the dealer index for which the responses are for
            Dictionary<int, List<DistResponse>> resps = [];

            for (int i = 0; i < deals.Count; i++)
            {
                resps[i] = [];
                var localDeals = deals[i];
                foreach (var d in localDeals)
                {
                    var dkg = newDkgs[d.Key];
                    var resp = dkg.ProcessDeal(d.Value);
                    Assert.That(resp, Is.Not.Null);
                    Assert.That(resp.VssResponse.Status, Is.EqualTo(ResponseStatus.Approval));
                    resps[i].Add(resp);

                    if (i == 0)
                    {
                        //Console.WriteLine($"dealer (oidx {newDkgs[i].oidx}, nidx {newDkgs[i].nidx}) processing deal to {i} from {d.Index}");
                    }
                }
            }

            // all new dkgs should have the same length of verifiers map
            foreach (var dkg in newDkgs)
            {
                // one deal per old participants
                Assert.That(dkg.Verifiers, Has.Count.EqualTo(oldN), $"dkg nidx {dkg.Nidx} failing");
            }

            // 2. Broadcast responses
            foreach (var dealResponses in resps)
            {
                foreach (var resp in dealResponses.Value)
                {
                    foreach (var dkg in totalDkgs)
                    {
                        // Ignore messages from ourselves
                        if (dkg.CanReceive && resp.VssResponse.Index == dkg.Nidx)
                        {
                            continue;
                        }

                        try
                        {
                            var j = dkg.ProcessResponse(resp);
                            // Console.WriteLine($"old dkg {dkg.Oidx} process responses from new dkg {dkg.Nidx} about deal {resp.Index}");
                        }
                        catch (DkgError ex)
                        {
                            Console.WriteLine($"old dkg at (oidx {dkg.Oidx}, nidx {dkg.Nidx}) has received response from idx " + 
                                              $"{resp.VssResponse.Index} for dealer idx {resp.Index}");
                            Assert.Fail(ex.Message);
                        }
                    }
                }
            }

            foreach (var dkg in newDkgs)
            {
                for (int i = 0; i < oldN; i++)
                {
                    Assert.That(dkg.Verifiers[i].DealCertified(), Is.True,
                                $"new dkg {dkg.Nidx} has not certified deal {i} => {dkg.Verifiers[i].Responses()}");
                }
            }

            // 3. make sure everyone has the same QUAL set
            foreach (var dkg in newDkgs)
            {
                foreach (var dkg2 in oldDkgs)
                {
                    Assert.That(dkg.IsInQUAL(dkg2.Oidx), Is.True,
                                $"new dkg {dkg.Nidx} has not in qual old dkg {dkg2.Oidx} (qual = {dkg.QUAL()})");
                }
            }

            var newShares = new DistKeyShare[newN];
            var newSShares = new PriShare[newN];

            for (int i = 0; i < newDkgs.Length; i++)
            {
                var dks = newDkgs[i].DistKeyShare();
                newShares[i] = dks;
                newSShares[i] = newShares[i].Share;
            }

            // check shares reconstruct to the same secret
            var oldSecret = PriPoly.RecoverSecret(_g, sshares, oldT, oldN);
            var newSecret = PriPoly.RecoverSecret(_g, newSShares, newT, newN);

            Assert.That(newSecret, Is.EqualTo(oldSecret));
        }

        // Helper functions
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