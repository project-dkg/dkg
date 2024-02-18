
namespace DkgTests
{
    internal class TestDkgPedersen
    {
        private const int DefaultN = 5;
        private static int DefaultT => VssTools.MinimumT(DefaultN);

        private IGroup _g = Suite.G;

        private (IScalar prv, IPoint pub) KeyPair()
        {
            var prv = _g.Scalar();
            var pub = _g.Point().Base().Mul(prv);
            return (prv, pub);
        }


        private (IPoint[] partPubs, IScalar[], List<DistKeyGenerator> dkgs) Generate(int n, int t)
               {
                   var partPubs = new IPoint[n];
                   var partSec = new IScalar[n];
                   for (int i = 0; i < n; i++)
                   {
                       var (sec, pub) = KeyPair();
                       partPubs[i] = pub;
                       partSec[i] = sec;
                   }
                   var dkgs = new List<DistKeyGenerator>(n);
/*                   for (int i = 0; i < n; i++)
                   {
                       var dkg = new DistKeyGenerator(partSec[i], partPubs, t);
                       dkgs[i] = dkg;
                   }*/
                   return (partPubs, partSec, dkgs);
               }

               [Test]
               public void TestDKGNewDistKeyGenerator()
               {
                   var (partPubs, partSec, _) = Generate(DefaultN, DefaultT);

                   var longSec = partSec[0];
            /*
                   var dkg = new DistKeyGenerator(longSec, partPubs, DefaultT);
                   Assert.IsNotNull(dkg.Dealer);
                   Assert.IsTrue(dkg.CanIssue);
                   Assert.IsTrue(dkg.CanReceive);
                   Assert.IsTrue(dkg.NewPresent);
                   // because we set old = new
                   Assert.IsTrue(dkg.OldPresent);
                   Assert.IsTrue(dkg.CanReceive);
                   Assert.IsFalse(dkg.IsResharing);

                   var (sec, _) = KeyPair();
                   Assert.Throws<Exception>(() => new DistKeyGenerator(sec, partPubs, DefaultT));

                   Assert.Throws<Exception>(() => new DistKeyGenerator(sec, new IPoint[], DefaultT));
            */
               }
    }
}
