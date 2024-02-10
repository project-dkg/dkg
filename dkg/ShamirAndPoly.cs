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
using System.Security.Cryptography;

[assembly: InternalsVisibleTo("testDkg")]

namespace dkg
{
    public class Share(int I)
    {
        public int I { get; set; } = I;
    }

    public class ShareComparer : IComparer<Share>
    {
        public int Compare(Share? x, Share? y)
        {
            ArgumentNullException.ThrowIfNull(x);
            ArgumentNullException.ThrowIfNull(y);
            return x!.I.CompareTo(y!.I);
        }
    }

    // PriShare represents a private share.
    public class PriShare(int I, IScalar V) : Share(I)
    {
        public IScalar V { get; set; } = V;

        // Returns the hash representation of this share
        public byte[] Hash(HashAlgorithm hashAlgorithm)
        {
            var h = hashAlgorithm.ComputeHash(V.GetBytes());
            var iBytes = BitConverter.GetBytes(I);
            h = [.. h, .. iBytes];
            return h;
        }

        public override string ToString()
        {
            return $"{{PriShare: I = {I}; V = {V}}}";
        }
    }

    // PriPoly represents a secret sharing polynomial.
    public class PriPoly: IEquatable<PriPoly>
    {
        private IGroup g; // Cryptographic group
        public IScalar[] Coeffs { get; } // Coefficients of the polynomial

        // Сreates a new secret sharing polynomial using the provided
        // cryptographic group, the secret sharing threshold t, and the secret to be
        // shared s. If s is nil, a new s is chosen using the provided randomness
        // stream rand.
        public PriPoly(IGroup group, int t, IScalar? s, RandomStream strm)
        {
            Coeffs = new IScalar[t];
            Coeffs[0] = s ?? group.Scalar().Pick(strm);
            for (int i = 1; i < t; i++)
            {
                Coeffs[i] = group.Scalar().Pick(strm);
            }
            g = group;
        }

        public PriPoly(IGroup g, IScalar[] coeffs)
        {
            this.g = g;
            this.Coeffs = coeffs;
        }

        public override bool Equals(object? obj)
        {
            return Equals(obj as PriPoly);
        }

        // Equals checks equality of two secret sharing polynomials p and q. If p and q are trivially
        // unequal (e.g., due to mismatching cryptographic groups or polynomial size), this routine
        // returns in variable time. Otherwise it runs in constant time regardless of whether it
        // eventually returns true or false.
        public bool Equals(PriPoly? q)
        {
            if (q == null)
            {
                return false;
            }
            if (g != q.g)
            {
                return false;
            }
            if (Coeffs.Length != q.Coeffs.Length)
            {
                return false;
            }
            for (int i = 0; i < Threshold(); i++)
            {
                if (!Coeffs[i].Equals(q.Coeffs[i]))
                {
                    return false;
                }
            }
            return true;
        }
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hash = 17;
                hash += g.GetHashCode();
                foreach (var coeff in Coeffs)
                {
                    hash = hash * 23 + coeff.GetHashCode();
                }
                return hash;
            }
        }

        // Threshold returns the secret sharing threshold.
        public int Threshold()
        {
            return Coeffs.Length;
        }

        // Secret returns the shared secret p(0), i.e., the constant term of the polynomial.
        public IScalar Secret()
        {
            return Coeffs[0];
        }

        // Eval computes the private share v = p(i).
        public PriShare Eval(int i)
        {
            var xi = g.Scalar().SetInt64(1 + i);
            var v = g.Scalar().Zero();
            for (int j = Threshold() - 1; j >= 0; j--)
            {
                v = v.Mul(xi);
                v = v.Add(Coeffs[j]);
            }
            return new PriShare(i, v);
        }

        // Shares creates an array of n private shares p(1),...,p(n).
        public PriShare[] Shares(int n)
        {
            var shares = new PriShare[n];
            for (int i = 0; i < n; i++)
            {
                shares[i] = Eval(i);
            }
            return shares;
        }

        // Add computes the component-wise sum of the polynomials p and q and returns it
        // as a new polynomial.
        public PriPoly Add(PriPoly q)
        {
            if (g != q.g)
            {
                throw new ArgumentException("PriPoly.Add: Non-matching groups");
            }
            if (Threshold() != q.Threshold())
            {
                throw new ArgumentException("PriPoly.Add: Different number of coefficients");
            }
            var newCoeffs = new IScalar[Threshold()];
            for (int i = 0; i < Threshold(); i++)
            {
                newCoeffs[i] = Coeffs[i].Add(q.Coeffs[i]);
            }
            return new PriPoly(g, newCoeffs);
        }

        // Commit creates a public commitment polynomial for the given base point b or
        // the standard base if b == nil.
        public PubPoly Commit()
        {
            return Commit(g.Point().Base());
        }
         public PubPoly Commit(IPoint b)
        {
            var commits = new IPoint[Threshold()];
            for (int i = 0; i < Threshold(); i++)
            {
                commits[i] = b.Mul(Coeffs[i]);
            }
            return new PubPoly(g, b, [.. commits]);
        }

        // Mul multiples p and q together. The result is a polynomial of the sum of
        // the two degrees of p and q. NOTE: it does not check for null coefficients
        // after the multiplication, so the degree of the polynomial is "always" as
        // described above. This is only for use in secret sharing schemes. It is not
        // a general polynomial multiplication routine.
        public PriPoly Mul(PriPoly q)
        {
            int d1 = Coeffs.Length - 1, d2 = q.Coeffs.Length - 1, newDegree = d1 + d2;
            var newCoeffs = new IScalar[newDegree + 1];
            for (int i = 0; i <= newDegree; i++)
            {
                newCoeffs[i] = g.Scalar().Zero();
            }
            for (int i = 0; i < Coeffs.Length; i++)
            {
                for (int j = 0; j < q.Coeffs.Length; j++)
                {
                    var tmp = Coeffs[i].Mul(q.Coeffs[j]);
                    newCoeffs[i + j] = newCoeffs[i + j].Add(tmp);
                }
            }
            return new PriPoly(g, newCoeffs);
        }

        // RecoverSecret reconstructs the shared secret p(0) from a list of private
        // shares using Lagrange interpolation.
        public static IScalar RecoverSecret(Secp256k1Group g, PriShare[] shares, int t, int n)
        {
            var (x, y) = XyScalar(g, shares, t, n);

            if (x.Count < t)
            {
                throw new ArgumentException("PriPoly.RecoverSecret: Not enough shares to recover secret");
            }

            IScalar num = g.Scalar(), den = g.Scalar(), acc = g.Scalar().Zero();

            foreach (int i in x.Keys)
            {
                num = num.Set(y[i]);
                den = den.One();
                foreach (int j in x.Keys)
                {
                    if (i == j)
                    {
                        continue;
                    }
                    num = num.Mul(x[j]);
                    den = den.Mul(x[j].Sub(x[i]));
                }
                acc = acc.Add(num.Div(den));
            }

            return acc;
        }

        // xyScalar returns the list of (x_i, y_i) pairs indexed. The first map returned
        // is the list of x_i and the second map is the list of y_i, both indexed in
        // their respective map at index i.
        public static (Dictionary<int, IScalar>, Dictionary<int, IScalar>) XyScalar(IGroup g, PriShare[] shares, int t, int n)
        {
            List<PriShare> sorted = shares.Where(s => s != null).ToList();
            sorted.Sort(new ShareComparer());

            var x = new Dictionary<int, IScalar>();
            var y = new Dictionary<int, IScalar>();
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
        // RecoverPriPoly takes a list of shares and the parameters t and n to
        // reconstruct the secret polynomial completely, i.e., all private
        // coefficients.  It is up to the caller to make sure that there are enough
        // shares to correctly re-construct the polynomial. There must be at least t
        // shares.
        public static PriPoly? RecoverPriPoly(IGroup g, PriShare[] shares, int t, int n)
        {
            var (x, y) = XyScalar(g, shares, t, n);
            if (x.Count != t)
            {
                throw new ArgumentException("PriPoly.RecoverPriPoly: Not enough shares to recover private polynomial");
            }

            PriPoly? accPoly = null;

            foreach (var j in x.Keys)
            {
                var basis = LagrangeBasis(g, j, x);
                for (var i = 0; i < basis.Coeffs.Length; i++)
                {
                    basis.Coeffs[i] = basis.Coeffs[i].Mul(y[j]);
                }

                if (accPoly == null)
                {
                    accPoly = basis;
                    continue;
                }

                accPoly = accPoly.Add(basis);
            }
            return accPoly;
        }
        public override string ToString()
        {
            var strs = Coeffs.Select(c => c.ToString()).ToList();
            return "[ " + string.Join(", ", strs) + " ]";
        }

        public static PriPoly MinusConst(IGroup g, IScalar c)
        {
            var neg = c.Neg();
            return new PriPoly(g, [neg, g.Scalar().One()]);
        }

        public static PriPoly LagrangeBasis(IGroup g, int i, Dictionary<int, IScalar> xs)
        {
            var basis = new PriPoly(g, [g.Scalar().One()]);

            var acc = g.Scalar().One();

            foreach (var pair in xs)
            {
                if (i == pair.Key)
                {
                    continue;
                }

                basis = basis.Mul(MinusConst(g, pair.Value));
                var den = xs[i].Sub(pair.Value); // den = xi - xm
                den = den.Inv(); // den = 1 / den
                acc = acc.Mul(den); // acc = acc * den
            }

            // multiply all coefficients by the denominator
            for (int j = 0; j < basis.Coeffs.Length; j++)
            {
                basis.Coeffs[j] = basis.Coeffs[j].Mul(acc);
            }

            return basis;
        }
    }

    // PubShare represents a public share.
    public class PubShare(int I, IPoint V) : Share(I)
    {
        public IPoint V { get; set; } = V;

        // Hash returns the hash representation of this share.
        public byte[] Hash(HashAlgorithm hashAlgorithm)
        {
            var h = hashAlgorithm.ComputeHash(V.GetBytes());
            var iBytes = BitConverter.GetBytes(I);
            h = [.. h, .. iBytes];
            return h;
        }
        public override string ToString()
        {
            return $"{{PubShare: I = {I}; V = {V}}}";
        }
    }

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
            {
                return false;
            }
            if (g != q.g)
            {
                return false;
            }
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