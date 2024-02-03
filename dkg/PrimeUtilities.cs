using System.Numerics;
using System.Security.Cryptography;

namespace Dkg
{
    public class PrimeUtilities
    {
        public PrimeUtilities()
        {
        }

        public bool IsProbablyPrime(BigInteger number, int witnesses = 5)
        {
            if (number < 2)
                return false;

            BigInteger d = number - 1;
            int s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                s++;
            }

            for (int i = 0; i < witnesses; i++)
            {
                BigInteger a = GenerateRandomNumber(2, number - 1);
                BigInteger x = BigInteger.ModPow(a, d, number);

                if (x == 1 || x == number - 1)
                    continue;

                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, number);
                    if (x == 1)
                        return false;
                    if (x == number - 1)
                        break;
                }

                if (x != number - 1)
                    return false;
            }

            return true;
        }
        public BigInteger GenerateRandomNumber(BigInteger min, BigInteger max)
        {
            byte[] bytes = new byte[max.ToByteArray().Length];
            BigInteger result;

            do
            {
                RandomNumberGenerator.Fill(bytes);
                result = new BigInteger(bytes);
            }
            while (result < min || result >= max);

            return result;
        }
        public BigInteger GenerateLargePrimeNumber(int bitLength = 2048)
        {
            byte[] bytes = new byte[bitLength / 8];
            BigInteger result;

            while (true)
            {
                RandomNumberGenerator.Fill(bytes);
                result = new BigInteger(bytes);

                // Make sure the number is odd and in the correct range
                if (result % 2 == 0)
                    result += 1;
                if (result < BigInteger.Pow(2, bitLength - 1) || result > BigInteger.Pow(2, bitLength))
                    continue;

                // Perform a probabilistic primality test
                if (IsProbablyPrime(result))
                    return result;
            }
        }
    }
}
