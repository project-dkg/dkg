// This file implements Shamir secret sharing and polynomial commitments.
// Shamir's scheme allows you to split a secret value into multiple parts, so called
// shares, by evaluating a secret sharing polynomial at certain indices. The
// shared secret can only be reconstructed (via Lagrange interpolation) if a
// threshold of the participants provide their shares. A polynomial commitment
// scheme allows a committer to commit to a secret sharing polynomial so that
// a verifier can check the claimed evaluations of the committed polynomial.
// Both schemes of this package are core building blocks for more advanced
// secret sharing techniques.

using System.Security.Cryptography;

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
    public class PriPoly
    {
        private IGroup g; // Cryptographic group
        private readonly List<IScalar> coeffs; // Coefficients of the polynomial

        // Сreates a new secret sharing polynomial using the provided
        // cryptographic group, the secret sharing threshold t, and the secret to be
        // shared s. If s is nil, a new s is chosen using the provided randomness
        // stream rand.
        public PriPoly(IGroup group, int t, IScalar? s, RandomStream strm)
        {
            coeffs = new List<IScalar>(t);
            coeffs[0] = s ?? group.Scalar().Pick(strm);
            for (int i = 1; i < t; i++)
            {
                coeffs[i] = group.Scalar().Pick(strm);
            }
            g = group;
        }

        public PriPoly(IGroup g, List<IScalar> coeffs)
        {
            this.g = g;
            this.coeffs = coeffs;
        }

        // Threshold returns the secret sharing threshold.
        public int Threshold()
        {
            return coeffs.Count;
        }

        // Secret returns the shared secret p(0), i.e., the constant term of the polynomial.
        public IScalar Secret()
        {
            return coeffs[0];
        }

        // Eval computes the private share v = p(i).
        public PriShare Eval(int i)
        {
            var xi = g.Scalar().SetInt64(1 + i);
            var v = g.Scalar().Zero();
            for (int j = Threshold() - 1; j >= 0; j--)
            {
                v.Mul(v, xi);
                v.Add(v, coeffs[j]);
            }
            return new PriShare(i, v);
        }

        // Shares creates a list of n private shares p(1),...,p(n).
        public List<PriShare> Shares(int n)
        {
            var shares = new List<PriShare>(n);
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
            if (g.ToString() != q.g.ToString())
            {
                throw new ArgumentException("non-matching groups");
            }
            if (Threshold() != q.Threshold())
            {
                throw new ArgumentException("different number of coefficients");
            }
            var newCoeffs = new List<IScalar>(Threshold());
            for (int i = 0; i < Threshold(); i++)
            {
                newCoeffs[i] = g.Scalar().Add(coeffs[i], q.coeffs[i]);
            }
            return new PriPoly(g, coeffs);
        }

        // Equals checks equality of two secret sharing polynomials p and q. If p and q are trivially
        // unequal (e.g., due to mismatching cryptographic groups or polynomial size), this routine
        // returns in variable time. Otherwise it runs in constant time regardless of whether it
        // eventually returns true or false.
        public bool Equals(PriPoly q)
        {
            if (g.ToString() != q.g.ToString())
            {
                return false;
            }
            if (coeffs.Count != q.coeffs.Count)
            {
                return false;
            }
            for (int i = 0; i < Threshold(); i++)
            {
                if (!coeffs[i].Equals(q.coeffs[i]))
                {
                    return false;
                }
            }
            return true;
        }

        // Commit creates a public commitment polynomial for the given base point b or
        // the standard base if b == nil.
        public PubPoly Commit(IPoint b)
        {
            var commits = new List<IPoint>(Threshold());
            for (int i = 0; i < Threshold(); i++)
            {
                commits[i] = g.Point().Mul(b, coeffs[i]);
            }
            return new PubPoly(g, b, commits);
        }

        // Mul multiples p and q together. The result is a polynomial of the sum of
        // the two degrees of p and q. NOTE: it does not check for null coefficients
        // after the multiplication, so the degree of the polynomial is "always" as
        // described above. This is only for use in secret sharing schemes. It is not
        // a general polynomial multiplication routine.
        public PriPoly Mul(PriPoly q)
        {
            int d1 = coeffs.Count - 1;
            int d2 = q.coeffs.Count - 1;
            int newDegree = d1 + d2;
            var newCoeffs = new List<IScalar>(newDegree + 1);
            for (int i = 0; i <= newDegree; i++)
            {
                newCoeffs[i] = g.Scalar().Zero();
            }
            for (int i = 0; i < coeffs.Count; i++)
            {
                for (int j = 0; j < q.coeffs.Count; j++)
                {
                    var tmp = g.Scalar().Mul(coeffs[i], q.coeffs[j]);
                    newCoeffs[i + j] = tmp.Add(newCoeffs[i + j], tmp);
                }
            }
            return new PriPoly(g, coeffs);
        }

        // Coefficients return the list of coefficients representing p. This
        // information is generally PRIVATE and should not be revealed to a third party
        // lightly.
        private List<IScalar> Coefficients()
        {
            return coeffs;
        }

        // RecoverSecret reconstructs the shared secret p(0) from a list of private
        // shares using Lagrange interpolation.
        public static IScalar RecoverSecret(IGroup g, List<PriShare> shares, int t, int n)
        {
            var x = new List<IScalar>();
            var y = new List<IScalar>();
            foreach (var share in shares)
            {
                if (share != null && share.V != null && share.I >= 0 && share.I < n)
                {
                    x.Add(g.Scalar().SetInt64(1 + share.I));
                    y.Add(share.V);
                }
            }
            if (x.Count < t)
            {
                throw new ArgumentException("not enough shares to recover secret");
            }
            var acc = g.Scalar().Zero();
            var num = g.Scalar();
            var den = g.Scalar();
            var tmp = g.Scalar();
            for (int i = 0; i < x.Count; i++)
            {
                var xi = x[i];
                var yi = y[i];
                num.Set(yi);
                den.One();
                for (int j = 0; j < x.Count; j++)
                {
                    if (i == j)
                    {
                        continue;
                    }
                    num.Mul(num, x[j]);
                    den.Mul(den, tmp.Sub(x[j], xi));
                }
                acc.Add(acc, num.Div(num, den));
            }
            return acc;
        }

        // xyScalar returns the list of (x_i, y_i) pairs indexed. The first map returned
        // is the list of x_i and the second map is the list of y_i, both indexed in
        // their respective map at index i.
        public static (Dictionary<int, IScalar>, Dictionary<int, IScalar>) XyScalar(IGroup g, List<PriShare> shares, int t, int n)
        {
            var sorted = shares.Where(s => s != null).ToList();
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
        public static PriPoly? RecoverPriPoly(IGroup g, List<PriShare> shares, int t, int n)
        {
            var (x, y) = XyScalar(g, shares, t, n);
            if (x.Count != t)
            {
                throw new Exception("share: not enough shares to recover private polynomial");
            }

            PriPoly? accPoly = null;

            foreach (var j in x.Keys)
            {
                var basis = LagrangeBasis(g, j, x);
                for (var i = 0; i < basis.coeffs.Count; i++)
                {
                    basis.coeffs[i] = basis.coeffs[i].Mul(basis.coeffs[i], y[j]);
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
            var strs = coeffs.Select(c => c.ToString()).ToList();
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
                var den = g.Scalar().Sub(xs[i], pair.Value); // den = xi - xm
                den = den.Inv(); // den = 1 / den
                acc = g.Scalar().Mul(acc, den); // acc = acc * den
            }

            // multiply all coefficients by the denominator
            for (int j = 0; j < basis.coeffs.Count; j++)
            {
                basis.coeffs[j] = g.Scalar().Mul(basis.coeffs[j], acc);
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
    public class PubPoly(IGroup group, IPoint basePoint, List<IPoint> commits)
    {
        private IGroup g = group; // Cryptographic group
        private IPoint b = basePoint; // Base point, null for standard base
        private List<IPoint> commits = commits; // Commitments to coefficients of the secret sharing polynomial

        // Info returns the base point and the commitments to the polynomial coefficients.
        public (IPoint, List<IPoint>) Info()
        {
            return (b, commits);
        }

        // Threshold returns the secret sharing threshold.
        public int Threshold()
        {
            return commits.Count;
        }

        // Commit returns the secret commitment p(0), i.e., the constant term of the polynomial.
        public IPoint Commit()
        {
            return commits[0];
        }

        // Eval computes the public share v = p(i).
        public PubShare Eval(int i)
        {
            var xi = g.Scalar().SetInt64(1 + i); // x-coordinate of this share
            var v = g.Point().Null();
            for (int j = Threshold() - 1; j >= 0; j--)
            {
                v.Mul(v, xi);
                v.Add(v, commits[j]);
            }
            return new PubShare(i, v);
        }

        // Shares creates a list of n public commitment shares p(1),...,p(n).
        public List<PubShare> Shares(int n)
        {
            var shares = new List<PubShare>(n);
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
            if (g.ToString() != q.g.ToString())
            {
                throw new ArgumentException("non-matching groups");
            }

            if (Threshold() != q.Threshold())
            {
                throw new ArgumentException("different number of coefficients");
            }

            var newCommits = new List<IPoint>(Threshold());
            for (int i = 0; i < Threshold(); i++)
            {
                newCommits[i] = g.Point().Add(commits[i], q.commits[i]);
            }

            return new PubPoly(g, b, newCommits);
        }

        // Equals checks equality of two public commitment polynomials p and q. If p and
        // q are trivially unequal (e.g., due to mismatching cryptographic groups),
        // this routine returns in variable time. Otherwise it runs in constant time
        // regardless of whether it eventually returns true or false.
        public bool Equals(PubPoly q)
        {
            if (g.ToString() != q.g.ToString())
            {
                return false;
            }
            for (int i = 0; i < Threshold(); i++)
            {
                if (!commits[i].Equals(q.commits[i]))
                {
                    return false;
                }
            }
            return true;
        }

        // Check a private share against a public commitment polynomial.
        public bool Check(PriShare s)
        {
            var pv = Eval(s.I);
            var ps = g.Point().Mul(b, s.V);
            return pv.V.Equals(ps);
        }

        public static (Dictionary<int, IScalar>, Dictionary<int, IPoint>) XyCommit(IGroup g, List<PubShare> shares, int t, int n)
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

        public static IPoint RecoverCommit(IGroup g, List<PubShare> shares, int t, int n)
        {
            var (x, y) = XyCommit(g, shares, t, n);

            if (x.Count < t)
            {
                throw new Exception("share: not enough good public shares to reconstruct secret commitment");
            }

            var num = g.Scalar();
            var den = g.Scalar();
            var tmp = g.Scalar();
            var acc = g.Point().Null();
            var tmpPoint = g.Point();

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

                    num.Mul(num, pair2.Value);
                    den.Mul(den, tmp.Sub(pair2.Value, pair.Value));
                }

                tmpPoint.Mul(y[pair.Key], num.Div(num, den));
                acc.Add(acc, tmpPoint);
            }

            return acc;
        }

        public static PubPoly? RecoverPubPoly(IGroup g, List<PubShare> shares, int t, int n)
        {
            var (x, y) = XyCommit(g, shares, t, n);

            if (x.Count < t)
            {
                throw new Exception("share: not enough good public shares to reconstruct secret commitment");
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