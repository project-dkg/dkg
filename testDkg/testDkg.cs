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

namespace DkgTests
{
    [TestFixture]
    public class DkgTests
    {
        [Test]
        public void TestRefreshDKG()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;

            // Run an n-fold Pedersen VSS (= DKG)
            var priPolys = new PriPoly[n];
            var priShares = new PriShare[n][];
            var pubPolys = new PubPoly[n];
            var pubShares = new PubShare[n][];
            for (int i = 0; i < n; i++)
            {
                priPolys[i] = new PriPoly(g, t, null, new RandomStream());
                priShares[i] = priPolys[i].Shares(n);
                pubPolys[i] = priPolys[i].Commit();
                pubShares[i] = pubPolys[i].Shares(n);
            }

            // Verify VSS shares
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    var sij = priShares[i][j];
                    // s_ij * G
                    var sijG = g.Point().Base().Mul(sij.V);
                    Assert.That(pubShares[i][j].V, Is.EqualTo(sijG));
                }
            }

            // Create private DKG shares
            var dkgShares = new PriShare[n];
            for (int i = 0; i < n; i++)
            {
                var acc = g.Scalar().Zero();
                for (int j = 0; j < n; j++) // assuming all participants are in the qualified set
                {
                    acc = acc.Add(priShares[j][i].V);
                }
                dkgShares[i] = new PriShare(i, acc);
            }

            // Create public DKG commitments (= verification vector)
            var dkgCommits = new IPoint[t];
            for (int k = 0; k < t; k++)
            {
                var acc = g.Point().Null();
                for (int i = 0; i < n; i++) // assuming all participants are in the qualified set
                {
                    var cmt = pubPolys[i].Commits;
                    acc = acc.Add(cmt[k]);
                }
                dkgCommits[k] = acc;
            }

            // Check that the private DKG shares verify against the public DKG commits
            var dkgPubPoly = new PubPoly(g, dkgCommits);
            for (int i = 0; i < n; i++)
            {
                Assert.That(dkgPubPoly.Check(dkgShares[i]), Is.True);
            }

            // Start verifiable resharing process
            var subPriPolys = new PriPoly[n];
            var subPriShares = new PriShare[n][];
            var subPubPolys = new PubPoly[n];
            var subPubShares = new PubShare[n][];

            // Create subshares and subpolys
            for (int i = 0; i < n; i++)
            {
                subPriPolys[i] = new PriPoly(g, t, dkgShares[i].V, new RandomStream());
                subPriShares[i] = subPriPolys[i].Shares(n);
                subPubPolys[i] = subPriPolys[i].Commit();
                subPubShares[i] = subPubPolys[i].Shares(n);
                Assert.That(subPubShares[i][0].V, Is.EqualTo(g.Point().Base().Mul(subPriShares[i][0].V)));
            }

            // Handout shares to new nodes column-wise and verify them
            var newDKGShares = new PriShare[n];
            for (int i = 0; i < n; i++)
            {
                var tmpPriShares = new PriShare[n]; // column-wise reshuffled sub-shares
                var tmpPubShares = new PubShare[n]; // public commitments to old DKG private shares
                for (int j = 0; j < n; j++)
                {
                    // Check 1: Verify that the received individual private subshares s_ji
                    // is correct by evaluating the public commitment vector
                    tmpPriShares[j] = new PriShare(j, subPriShares[j][i].V); // Shares that participant i gets from j
                    Assert.That(subPubPolys[j].Eval(i).V, Is.EqualTo(g.Point().Base().Mul(tmpPriShares[j].V)));

                    // Check 2: Verify that the received sub public shares are
                    // commitments to the original secret
                    tmpPubShares[j] = dkgPubPoly.Eval(j);
                    Assert.That(subPubPolys[j].Commit(), Is.EqualTo(tmpPubShares[j].V));
                }
                // Check 3: Verify that the received public shares interpolate to the
                // original DKG public key
                var com = PubPoly.RecoverCommit(g, tmpPubShares, t, n);
                Assert.That(com, Is.EqualTo(dkgCommits[0]));

                // Compute the refreshed private DKG share of node i
                var s = PriPoly.RecoverSecret(g, tmpPriShares, t, n);
                newDKGShares[i] = new PriShare(i, s);
            }

            // Refresh the DKG commitments (= verification vector)
            var newDKGCommits = new IPoint[t];
            for (int i = 0; i < t; i++)
            {
                var pShares = new PubShare[n];
                for (int j = 0; j < n; j++)
                {
                    var cmt = subPubPolys[j].Commits;
                    pShares[j] = new PubShare(j, cmt[i]);
                }
                var com = PubPoly.RecoverCommit(g, pShares, t, n);
                newDKGCommits[i] = com;
            }

            // Check that the old and new DKG public keys are the same
            Assert.That(newDKGCommits[0], Is.EqualTo(dkgCommits[0]));

            // Check that the old and new DKG private shares are different
            for (int i = 0; i < n; i++)
            {
                Assert.That(newDKGShares[i].V, Is.Not.EqualTo(dkgShares[i].V));
            }

            // Check that the refreshed private DKG shares verify against the refreshed public DKG commits
            var q = new PubPoly(g, newDKGCommits);
            for (int i = 0; i < n; i++)
            {
                Assert.That(q.Check(newDKGShares[i]), Is.True);
            }

            // Recover the private polynomial
            var refreshedPriPoly = PriPoly.RecoverPriPoly(g, newDKGShares, t, n);

            // Check that the secret and the corresponding (old) public commit match
            Assert.That(dkgCommits[0], Is.EqualTo(g.Point().Base().Mul(refreshedPriPoly!.Secret())));
        }
    }
}
