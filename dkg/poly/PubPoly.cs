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

// This file implements Shamir secret sharing and polynomial commitments.
// Shamir's scheme allows you to split a secret value into multiple parts, so called
// shares, by evaluating a secret sharing polynomial at certain indices. The
// shared secret can only be reconstructed (via Lagrange interpolation) if a
// threshold of the participants provide their shares. A polynomial commitment
// scheme allows a committer to commit to a secret sharing polynomial so that
// a verifier can check the claimed evaluations of the committed polynomial.

using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("testDkg")]

namespace dkg
{

    // PubPoly represents a public commitment polynomial to a secret sharing polynomial.
    public class PubPoly(IGroup group, IPoint basePoint, IPoint[] cmt) : IEquatable<PubPoly>
    {
        private readonly IGroup g = group; // Cryptographic group
        private readonly IPoint b = basePoint; // Base point, null for standard base
        public IPoint[] Commits { get; } = cmt; // Commitments to coefficients of the secret sharing polynomial

        public PubPoly(IGroup group, IPoint[] cmt) : this(group, group.Point().Base(), cmt)
        {
        }
        public override bool Equals(object? obj)
        {
            return Equals(obj as PubPoly);
        }

        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hash = 17;
                hash = hash + g.GetHashCode();
                hash = hash * 23 + b.GetHashCode();
                foreach (var commit in Commits)
                {
                    hash = hash * 23 + commit.GetHashCode();
                }
                return hash;
            }
        }

        // Equals checks equality of two public commitment polynomials p and q. If p and
        // q are trivially unequal (e.g., due to mismatching cryptographic groups),
        // this routine returns in variable time. Otherwise it runs in constant time
        // regardless of whether it eventually returns true or false.
        public bool Equals(PubPoly? q)
        {
            if (q == null)
                return false;

            if (ReferenceEquals(this, q))
                return true;


            if (g != q.g)
                return false;

            for (int i = 0; i < Threshold(); i++)
            {
                if (!Commits[i].Equals(q.Commits[i]))
                {
                    return false;
                }
            }
            return true;
        }

        // Threshold returns the secret sharing threshold.
        public int Threshold()
        {
            return Commits.Length;
        }

        // Commit returns the secret commitment p(0), i.e., the constant term of the polynomial.
        public IPoint Commit()
        {
            return Commits[0];
        }

        // Eval computes the public share v = p(i).
        public PubShare Eval(int i)
        {
            var xi = g.Scalar().SetInt64(1 + i); // x-coordinate of this share
            var v = g.Point().Null();
            for (int j = Threshold() - 1; j >= 0; j--)
            {
                v = v.Mul(xi);
                v = v.Add(Commits[j]);
            }
            return new PubShare(i, v);
        }

        // Shares creates a list of n public commitment shares p(1),...,p(n).
        public PubShare[] Shares(int n)
        {
            var shares = new PubShare[n];
            for (int i = 0; i < n; i++)
            {
                shares[i] = Eval(i);
            }
            return shares;
        }

        // Add computes the component-wise sum of the polynomials p and q and returns it
        // as a new polynomial. NOTE: If the base points p.b and q.b are different then the
        // base point of the resulting PubPoly cannot be computed without knowing the
        // discrete logarithm between p.b and q.b. In this particular case, we are using
        // p.b as a default value which of course does not correspond to the correct
        // base point and thus should not be used in further computations.
        public PubPoly Add(PubPoly q)
        {
            if (g != q.g)
            {
                throw new ArgumentException("non-matching groups");
            }

            if (Threshold() != q.Threshold())
            {
                throw new ArgumentException("different number of coefficients");
            }

            var newCommits = new IPoint[Threshold()];
            for (int i = 0; i < Threshold(); i++)
            {
                newCommits[i] = Commits[i].Add(q.Commits[i]);
            }

            return new PubPoly(g, b, newCommits);
        }

        // Check a private share against a public commitment polynomial.
        public bool Check(PriShare s)
        {
            var pv = Eval(s.I);
            var ps = b.Mul(s.V);
            return pv.V.Equals(ps);
        }

        public static (Dictionary<int, IScalar>, Dictionary<int, IPoint>) XyCommit(IGroup g, PubShare[] shares, int t, int n)
        {
            var sorted = shares.Where(s => s != null).ToList();
            sorted.Sort(new ShareComparer());

            var x = new Dictionary<int, IScalar>();
            var y = new Dictionary<int, IPoint>();

            foreach (var s in sorted)
            {
                if (s == null || s.V == null || s.I < 0)
                {
                    continue;
                }

                var idx = s.I;
                x[idx] = g.Scalar().SetInt64(idx + 1);
                y[idx] = s.V;

                if (x.Count == t)
                {
                    break;
                }
            }

            return (x, y);
        }

        public static IPoint RecoverCommit(IGroup g, PubShare[] shares, int t, int n)
        {
            var (x, y) = XyCommit(g, shares, t, n);

            if (x.Count < t)
            {
                throw new ArgumentException("PubPoly.RecoverCommit: not enough good public shares to reconstruct secret commitment");
            }

            IScalar num = g.Scalar(), den = g.Scalar();
            IPoint acc = g.Point().Null();

            foreach (var pair in x)
            {
                num.One();
                den.One();

                foreach (var pair2 in x)
                {
                    if (pair.Key == pair2.Key)
                    {
                        continue;
                    }

                    num = num.Mul(pair2.Value);
                    den = den.Mul(pair2.Value.Sub(pair.Value));
                }
                acc = acc.Add(y[pair.Key].Mul(num.Div(den)));
            }

            return acc;
        }

        public static PubPoly? RecoverPubPoly(IGroup g, PubShare[] shares, int t, int n)
        {
            var (x, y) = XyCommit(g, shares, t, n);

            if (x.Count < t)
            {
                throw new Exception("PubPoly.PubPoly: not enough good public shares to reconstruct secret commitment");
            }

            PubPoly? accPoly = null;

            foreach (var pair in x)
            {
                var basis = PriPoly.LagrangeBasis(g, pair.Key, x);

                // compute the L_j * y_j polynomial in point space
                var tmp = basis.Commit(y[pair.Key]);

                if (accPoly == null)
                {
                    accPoly = tmp;
                    continue;
                }

                // add all L_j * y_j together
                accPoly = accPoly.Add(tmp);
            }

            return accPoly;
        }
    }
}