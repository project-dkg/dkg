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

namespace ShamirAndPolyTests
{
    [TestFixture]
    public class SecretTests
    {
        [Test]
        public void TestSecretRecovery()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;
            var poly = new PriPoly(g, t, null, new RandomStream());
            var shares = poly.Shares(n);

            var recovered = PriPoly.RecoverSecret(g, shares, t, n);
            if (recovered == null)
            {
                Assert.Fail("Error recovering secret");
            }

            Assert.That(recovered, Is.EqualTo(poly.Secret()), "Recovered secret does not match initial value");
        }

        // tests the recovery of a secret when one of the share has an index
        // higher than the given `n`. This is a valid scenario that can happen during
        // a DKG-resharing:
        // 1. we add a new node n6 to an already-established group of 5 nodes.
        // 2. DKG runs without the first node in the group, i.e. without n1
        // 3. The list of qualified shares are [n2 ... n6] so the new resulting group
        //    has 5 members (no need to keep the 1st node around).
        // 4. When n6 wants to reconstruct, it will give its index given during the
        // resharing, i.e. 6 (or 5 in 0-based indexing) whereas n = 5.
        // See TestPublicRecoveryOutIndex for testing with the commitment.
        [Test]
        public void TestSecretRecoveryOutIndex()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;
            var poly = new PriPoly(g, t, null, new RandomStream());
            var shares = poly.Shares(n);

            var selected = shares.ToList().GetRange(n - t, t);
            Assert.That(selected, Has.Count.EqualTo(t));

            var recovered = PriPoly.RecoverSecret(g, [.. selected], t, t + 1);
            if (recovered == null)
            {
                Assert.Fail("Error recovering secret");
            }

            Assert.That(recovered, Is.EqualTo(poly.Secret()), "Recovered secret does not match initial value");
        }

        [Test]
        public void TestSecretRecoveryNotEnough()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;
            var poly = new PriPoly(g, t, null, new RandomStream());
            var shares = poly.Shares(n);

            var selected = shares.ToList().GetRange(n - t, t - 1);
            Assert.That(selected, Has.Count.EqualTo(t - 1));

            Assert.Throws<ArgumentException>(() => PriPoly.RecoverSecret(g, [.. selected], t, t));
        }

        [Test]
        public void TestSecretRecoveryDelete()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;
            var poly = new PriPoly(g, t, null, new RandomStream());
            var shares = poly.Shares(n).ToList();

            // Remove a few shares
            shares.RemoveAt(7);
            shares.RemoveAt(5);
            shares.RemoveAt(2);
            shares.RemoveAt(1);

            var recovered = PriPoly.RecoverSecret(g, [.. shares], shares.Count, n);
            if (recovered == null)
            {
                Assert.Fail("Error recovering secret");
            }

            Assert.That(recovered, Is.EqualTo(poly.Secret()), "Recovered secret does not match initial value");
        }
    }

    [TestFixture]
    public class PriPolyTests
    {
        [Test]
        public void TestPriPolyEqual()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;

            PriPoly p1 = new(g, t, null, new RandomStream());
            PriPoly p2 = new(g, t, null, new RandomStream());
            PriPoly p3 = new(g, t, null, new RandomStream());

            PriPoly p12 = p1.Add(p2);
            PriPoly p13 = p1.Add(p3);

            PriPoly p123 = p12.Add(p3);
            PriPoly p132 = p13.Add(p2);

            Assert.That(p132, Is.EqualTo(p123), "Private polynomials not equal");
        }
        [Test]
        public void TestPriPolyAdd()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;

            var p = new PriPoly(g, t, null, new RandomStream());
            var q = new PriPoly(g, t, null, new RandomStream());

            var r = p.Add(q);

            var ps = p.Secret();
            var qs = q.Secret();
            var rs = ps.Add(qs);

            Assert.That(rs, Is.EqualTo(r.Secret()), "Addition of secret sharing polynomials failed");
        }

        [Test]
        public void TestPriPolyMul()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;
            var a = new PriPoly(g, t, null, new RandomStream());
            var b = new PriPoly(g, t, null, new RandomStream());

            var c = a.Mul(b);
            Assert.That(c.Coeffs, Has.Length.EqualTo(a.Coeffs.Length + b.Coeffs.Length - 1));

            var zero = g.Scalar().Zero();
            foreach (var coeff in c.Coeffs)
            {
                Assert.That(coeff.ToString(), Is.Not.EqualTo(zero.ToString()));
            }

            var a0 = a.Coeffs[0];
            var b0 = b.Coeffs[0];
            var mul = b0.Mul(a0);
            var c0 = c.Coeffs[0];
            Assert.That(mul.ToString(), Is.EqualTo(c0.ToString()));

            var at = a.Coeffs[^1];
            var bt = b.Coeffs[^1];
            mul = at.Mul(bt);
            var ct = c.Coeffs[^1];
            Assert.That(mul.ToString(), Is.EqualTo(ct.ToString()));
        }

        [Test]
        public void TestPriPolyRecover()
        {
            var suite = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;
            var a = new PriPoly(suite, t, null, new RandomStream());

            var shares = a.Shares(n);
            var reverses = shares;
            reverses.Reverse();

            var recovered = PriPoly.RecoverPriPoly(suite, shares, t, n);
            Assert.That(recovered, Is.Not.Null);

            var reverseRecovered = PriPoly.RecoverPriPoly(suite, reverses, t, n);
            Assert.That(reverseRecovered, Is.Not.Null);

            for (int i = 0; i < t; i++)
            {
                Assert.That(a.Eval(i).V.ToString(), Is.EqualTo(recovered.Eval(i).V.ToString()));
                Assert.That(a.Eval(i).V.ToString(), Is.EqualTo(reverseRecovered.Eval(i).V.ToString()));
            }
        }
 
        [Test]
        public void TestPriPolyCoefficients()
        {
            var suite = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;
            var a = new PriPoly(suite, t, null, new RandomStream());

            var coeffs = a.Coeffs;
            Assert.That(t, Is.EqualTo(coeffs.Length));

            var b = new PriPoly(suite, coeffs);
            CollectionAssert.AreEqual(a.Coeffs, b.Coeffs);
        }
    }

    [TestFixture]
    public class PubPolyTests
    {
        [Test]
        public void TestPubPolyAdd()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;

            var G = g.Point().Pick(new RandomStream());
            var H = g.Point().Pick(new RandomStream());

            var p = new PriPoly(g, t, null, new RandomStream());
            var q = new PriPoly(g, t, null, new RandomStream());

            var P = p.Commit(G);
            var Q = q.Commit(H);

            var R = P.Add(Q);

            var shares = R.Shares(n);
            var recovered = PubPoly.RecoverCommit(g, shares, t, n);

            var x = P.Commit();
            var y = Q.Commit();
            var z = x.Add(y);

            Assert.That(recovered, Is.EqualTo(z), "Addition of public commitment polynomials failed");
        }

        [Test]
        public void TestPubPolyEqual()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;

            var G = g.Point().Pick(new RandomStream());

            var p1 = new PriPoly(g, t, null, new RandomStream());
            var p2 = new PriPoly(g, t, null, new RandomStream());
            var p3 = new PriPoly(g, t, null, new RandomStream());

            var P1 = p1.Commit(G);
            var P2 = p2.Commit(G);
            var P3 = p3.Commit(G);

            var P12 = P1.Add(P2);
            var P13 = P1.Add(P3);

            var P123 = P12.Add(P3);
            var P132 = P13.Add(P2);

            Assert.That(P132, Is.EqualTo(P123), "Public polynomials not equal");
        }

        [Test]
        public void TestPubPolyCheck()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;

            var priPoly = new PriPoly(g, t, null, new RandomStream());
            var priShares = priPoly.Shares(n);
            var pubPoly = priPoly.Commit();

            for (int i = 0; i < priShares.Length; i++)
            {
                var share = priShares[i];
                if (!pubPoly.Check(share))
                {
                    Assert.Fail($"Private share {i} not valid with respect to the public commitment polynomial");
                }
            }
        }

        [Test]
        public void TestPubPolyRecovery()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;

            var priPoly = new PriPoly(g, t, null, new RandomStream());
            var pubPoly = priPoly.Commit();
            var pubShares = pubPoly.Shares(n);

            var recovered = PubPoly.RecoverCommit(g, pubShares, t, n);
            Assert.That(recovered, Is.EqualTo(pubPoly.Commit()), "Recovered commit does not match initial value");

            var polyRecovered = PubPoly.RecoverPubPoly(g, pubShares, t, n);
            Assert.That(polyRecovered, Is.EqualTo(pubPoly), "Recovered polynomial does not match initial value");
        }

        [Test]
        public void TestPubPolyRecoveryOutIndex()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;

            var priPoly = new PriPoly(g, t, null, new RandomStream());
            var pubPoly = priPoly.Commit(g.Point().Base());
            var pubShares = pubPoly.Shares(n);

            var selected = pubShares.Skip(n - t).ToArray();
            Assert.That(selected, Has.Length.EqualTo(t));

            var recovered = PubPoly.RecoverCommit(g, selected, t, t + 1);
            Assert.That(recovered, Is.EqualTo(pubPoly.Commit()), "Recovered commit does not match initial value");

            var polyRecovered = PubPoly.RecoverPubPoly(g, pubShares, t, n);
            Assert.That(polyRecovered, Is.EqualTo(pubPoly), "Recovered polynomial does not match initial value");
        }

        [Test]
        public void TestPubPolyRecoveryDelete()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;

            var priPoly = new PriPoly(g, t, null, new RandomStream());
            var pubPoly = priPoly.Commit();
            var shares = pubPoly.Shares(n).ToList();

            // Remove a few shares
            shares.RemoveAt(8);
            shares.RemoveAt(7);
            shares.RemoveAt(5);
            shares.RemoveAt(2);

            var recovered = PubPoly.RecoverCommit(g, [..shares], t, n);
            Assert.That(recovered, Is.EqualTo(pubPoly.Commit()), "Recovered commit does not match initial value");
        }

        [Test]
        public void TestPubPolycRecoveryDeleteFail()
        {
            var g = new Secp256k1Group();
            int n = 10;
            int t = n / 2 + 1;

            var priPoly = new PriPoly(g, t, null, new RandomStream());
            var pubPoly = priPoly.Commit();
            var shares = pubPoly.Shares(n).ToList();

            // Remove one more share than acceptable
            shares.RemoveAt(8);
            shares.RemoveAt(7);
            shares.RemoveAt(5);
            shares.RemoveAt(2);
            shares.RemoveAt(1);

            Assert.Throws<ArgumentException>(() => PubPoly.RecoverCommit(g, [..shares], t, n));
        }
    }
}
