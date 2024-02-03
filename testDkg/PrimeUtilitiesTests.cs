using System.Numerics;

namespace Dkg.Tests
{
    public class PrimeUtilitiesTests
    {
        private PrimeUtilities utilities;

        [SetUp]
        public void Setup()
        {
            utilities = new PrimeUtilities();
        }

        [Test]
        public void TestIsProbablyPrimeWithPrimeNumber()
        {
            BigInteger primeNumber = new(13);
            Assert.That(utilities.IsProbablyPrime(primeNumber));
        }

        [Test]
        public void TestIsProbablyPrimeWithCompositeNumber()
        {
            BigInteger compositeNumber = new(15);
            Assert.That(utilities.IsProbablyPrime(compositeNumber), Is.False);
        }

        [Test]
        public void TestGenerateRandomNumber()
        {
            BigInteger min = new(1);
            BigInteger max = new(100);
            BigInteger randomNumber = utilities.GenerateRandomNumber(min, max);

            Assert.That(randomNumber, Is.GreaterThanOrEqualTo(min));
            Assert.That(randomNumber, Is.LessThan(max));
        }
    }
}