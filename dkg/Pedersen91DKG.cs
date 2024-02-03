using System.Numerics;

namespace Dkg
{
    public class Pedersen91DKG
    {
        private BigInteger p, q, g;
        private BigInteger[] coefficients;
        private int n, t;
        private PrimeUtilities util;

        public Pedersen91DKG()
        {
            util = new PrimeUtilities();
        }

        public void Initialize(int n, int t)
        {
            this.n = n;
            this.t = t;

            // Generate prime numbers p and q, where p = 2q + 1
            do
            {
                q = util.GenerateLargePrimeNumber();
                p = 2 * q + 1;
            } while (!util.IsProbablyPrime(p));

            // Generate a generator of the multiplicative group
            do
            {
                g = util.GenerateRandomNumber(1, p - 1) + 1;
            } while (BigInteger.ModPow(g, 2, p) == 1 || BigInteger.ModPow(g, q, p) == 1);

            // Generate the coefficients of the polynomial
            coefficients = new BigInteger[t];
            for (int i = 0; i < t; i++)
            {
                coefficients[i] = util.GenerateRandomNumber(1, q);
            }
        }

        public BigInteger ComputeShare(int j)
        {
            BigInteger result = coefficients[0];
            BigInteger exponent = new BigInteger(j);

            for (int i = 1; i < t; i++)
            {
                result = (result + coefficients[i] * BigInteger.Pow(exponent, i)) % q;
            }

            return result;
        }
    }
}
