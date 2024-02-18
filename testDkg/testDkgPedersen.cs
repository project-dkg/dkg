
using Google.Protobuf.WellKnownTypes;
using Org.BouncyCastle.Pqc.Crypto.Lms;

namespace DkgTests
{
    internal class TestDkgPedersen
    {
        private const int DefaultN = 5;
        private static int DefaultT => VssTools.MinimumT(DefaultN);

        private IGroup _g = Suite.G;

        RandomStream _randomStream;
        BinaryReader _randomReader;

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

        [SetUp]
        public void Setup()
        {
            _randomStream = new();
            _randomReader = new(_randomStream);
        }

        [Test]
        public void TestDKGNewDistKeyGenerator()
        {
            var (partPubs, partSec, _) = Generate(DefaultN, DefaultT);

            var longSec = partSec[0];

            var dkg = DistKeyGenerator.CreateDistKeyGenerator(longSec, partPubs, DefaultT);
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
            Assert.Throws<DkgError>(() => DistKeyGenerator.CreateDistKeyGenerator(sec, partPubs, DefaultT));
            IPoint[] empty = [];
            Assert.Throws<DkgError>(() => DistKeyGenerator.CreateDistKeyGenerator(sec, empty, DefaultT));
        }

        [Test]
        public void TestDKGProcessDeal()
        {
            var (_, _, dkgs) = Generate(DefaultN, DefaultT);
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
            // rec.ProcessDeal(deal);
            // Assert.Throws<DkgError>(() => rec.ProcessDeal(deal));

            // wrong index
            var goodIdx = deal.Index;
            deal.Index = DefaultN + 1;
            Assert.Throws<DkgError>(() => rec.ProcessDeal(deal));
            deal.Index = goodIdx;

            // wrong deal
            var goodSig = deal.VssDeal.Signature;
            deal.VssDeal.Signature = _randomReader.ReadBytes(goodSig.Length);  
            Assert.Throws<DkgError>(() => rec.ProcessDeal(deal));
            deal.VssDeal.Signature = goodSig;
}
    }
}