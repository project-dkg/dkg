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

using System.Text;

namespace Secp256k1Tests
{
    internal class Secp256k1ScalarTests
    {
        private Secp256k1Scalar _scalar;
        private IScalar _zero;
        private IScalar _one;

        [SetUp]
        public void Setup()
        {
            _scalar = new Secp256k1Scalar();
            _zero = new Secp256k1Scalar().Zero();
            _one = new Secp256k1Scalar().One();
        }

        [Test]
        public void TestEquals()
        {
            _scalar.Pick(new RandomStream());
            Assert.That(_scalar, Is.Not.EqualTo(null));

            Secp256k1Scalar? scalar2 = new();
            scalar2.Pick(new RandomStream());
            Assert.That(_scalar, Is.Not.EqualTo(scalar2));

            object? obj = new Secp256k1Point();
            Assert.That(_scalar, Is.Not.EqualTo(obj));

            scalar2 = _scalar.Clone() as Secp256k1Scalar;
            obj = scalar2;
            Assert.That(_scalar, Is.EqualTo(obj));
        }

        [Test]
        public void TestPick()
        {
            _scalar.Pick(new RandomStream());
            Secp256k1Scalar scalar2 = new();
            scalar2.Pick(new RandomStream());
            Assert.That(_scalar, Is.Not.EqualTo(scalar2));
        }

        [Test]
        public void TestClone()
        {
            _scalar.Pick(new RandomStream());
            Secp256k1Scalar? scalar2 = _scalar.Clone() as Secp256k1Scalar;
            Assert.That(_scalar, Is.EqualTo(scalar2));
        }

        [Test]
        public void TestSet()
        {
            _scalar.Pick(new RandomStream());
            Secp256k1Scalar scalar2 = new();
            scalar2.Set(_scalar);
            Assert.That(_scalar, Is.EqualTo(scalar2));
        }

        [Test]
        public void TestZero()
        {
            _scalar.Pick(new RandomStream());
            _scalar.Zero();
            Assert.That(_scalar.GetValue().IntValue, Is.EqualTo(0));
        }

        [Test]
        public void TestOne()
        {
            _scalar.Pick(new RandomStream());
            _scalar.One();
            Assert.That(_scalar.GetValue().IntValue, Is.EqualTo(1));
        }

        [Test]
        public void TestAddNeg()
        {
            _scalar.Pick(new RandomStream());
            IScalar scalar2 = _scalar.Neg();
            scalar2 = _scalar.Add(scalar2);
            Assert.That(_zero, Is.EqualTo(scalar2));
        }

        [Test]
        public void TestAddSub()
        {
            _scalar.Pick(new RandomStream());
            IScalar scalar2 = _scalar.Clone();
            scalar2 = _scalar.Sub(scalar2);
            Assert.That(_zero, Is.EqualTo(scalar2));
        }

        [Test]
        public void TestMulInv()
        {
            // ensure that the scalar is not zero or one,
            // because these values are not relatively prime to the order of the group
            // and the inverse does not exist
            do
            {
                _scalar.Pick(new RandomStream());
            } while (_scalar.Equals(_zero) || _scalar.Equals(_one));

            IScalar scalar2 = _scalar.Inv();
            scalar2 = _scalar.Mul(scalar2);
            Assert.That(_one, Is.EqualTo(scalar2));
        }

        [Test]
        public void TestMulDiv()
        {
            // ensure that the scalar is not zero or one,
            // because these values are not relatively prime to the order of the group
            // and the inverse does not exist
            do
            {
                _scalar.Pick(new RandomStream());
            } while (_scalar.Equals(_zero) || _scalar.Equals(_one));

            _scalar.Pick(new RandomStream());
            IScalar scalar2 = _scalar.Clone();
            scalar2 = _scalar.Div(scalar2);
            Assert.That(_one, Is.EqualTo(scalar2));
        }

        [Test]
        public void TestGetSetBytes()
        {
            _scalar.Pick(new RandomStream());
            byte[] bytes = _scalar.GetBytes();
            Secp256k1Scalar scalar2 = new();
            scalar2.SetBytes(bytes);
            Assert.That(_scalar.Equals(scalar2));
        }

        [Test]
        public void TestMarshalUnmarshalBinary()
        {
            _scalar.Pick(new RandomStream());
            MemoryStream stream = new();
            _scalar.MarshalBinary(stream);
            Assert.That(stream.Length, Is.EqualTo(_scalar.MarshalSize()));
            stream.Position = 0;
            Secp256k1Scalar scalar2 = new();
            scalar2.UnmarshalBinary(stream);
            Assert.That(_scalar.Equals(scalar2));
        }
    }

    public class Secp256k1PointTests
    {
        private Secp256k1Point _point;

        [SetUp]
        public void Setup()
        {
            _point = new Secp256k1Point();
        }

        [Test]
        public void TestEquals()
        {
            _point.Pick(new RandomStream());
            Assert.That(_point, Is.Not.EqualTo(null));

            Secp256k1Point? point2 = new();
            point2.Pick(new RandomStream());
            Assert.That(_point, Is.Not.EqualTo(point2));

            point2 = _point.Clone() as Secp256k1Point;
            object? obj = point2;
            Assert.That(_point, Is.EqualTo(obj));
        }

        [Test]
        public void TestPick()
        {
            _point.Pick(new RandomStream());
            Secp256k1Point point2 = new();
            point2.Pick(new RandomStream());
            Assert.That(_point, Is.Not.EqualTo(point2));
        }

        [Test]
        public void TestClone()
        {
            _point.Pick(new RandomStream());
            Secp256k1Point? point2 = _point.Clone() as Secp256k1Point;
            Assert.That(_point, Is.EqualTo(point2));
        }

        [Test]
        public void TestSet()
        {
            _point.Pick(new RandomStream());
            Secp256k1Point point2 = new();
            point2.Set(_point);
            Assert.That(_point, Is.EqualTo(point2));
        }

        [Test]
        public void TestAddNull()
        {
            _point.Pick(new RandomStream());
            IPoint point2 = _point.Null();
            point2 = _point.Add(point2);
            Assert.That(_point, Is.EqualTo(point2));
        }

        [Test]
        public void TestAddNeg()
        {
            _point.Pick(new RandomStream());
            IPoint point2 = _point.Neg();
            point2 = _point.Add(point2);
            point2 = _point.Add(point2);
            // point + (-point) + (-point) = -point
            Assert.That(_point, Is.EqualTo(point2));
        }

        [Test]
        public void TestAddSub()
        {
            _point.Pick(new RandomStream());
            IPoint point2 = _point.Clone();
            point2 = _point.Sub(point2);
            point2 = _point.Add(point2);
            // point - point + point = point
            Assert.That(_point, Is.EqualTo(point2));
        }

        [Test]
        public void TestGetSetBytes()
        {
            _point.Pick(new RandomStream());
            byte[] bytes = _point.GetBytes();
            Secp256k1Point point2 = new(); 
            point2.Pick(new RandomStream());
            point2.SetBytes(bytes);
            Assert.That(_point.Equals(point2));
        }

        [Test]
        public void TestMarshalUnmarshalBinary()
        {
            _point.Pick(new RandomStream());
            MemoryStream stream = new();
            _point.MarshalBinary(stream);
            Assert.That(stream.Length, Is.EqualTo(_point.MarshalSize()));
            stream.Position = 0;
            Secp256k1Point point2 = new();
            point2.UnmarshalBinary(stream);
            Assert.That(_point.Equals(point2));
        }
    }

    public class Secp256k1GroupTests
    {
        private Secp256k1Group _group;

        [SetUp]
        public void Setup()
        {
            _group = new Secp256k1Group();
        }

        [Test]
        public void TestScalarLen()
        {
            int scalarLen = _group.ScalarLen();
            Assert.That(scalarLen, Is.EqualTo(32));
        }

        [Test]
        public void TestPointLen()
        {
            int pointLen = _group.PointLen();
            Assert.That(pointLen, Is.EqualTo(33));
        }

        [Test]
        public void TestScalar()
        {
            IScalar scalar = _group.Scalar();
            Assert.That(scalar, Is.InstanceOf<Secp256k1Scalar>());
        }

        [Test]
        public void TestPoint()
        {
            IPoint point = _group.Point();
            Assert.That(point, Is.InstanceOf<Secp256k1Point>());
        }

        [Test]
        public void TestEmbed()
        {
            string message = "Hello, world!";
            byte[] plainData = Encoding.UTF8.GetBytes(message);
            var embedded = _group.EmbedData(plainData);

            var extractedData = embedded.ExtractData();
            Assert.Multiple(() =>
            {
                Assert.That(plainData, Is.EqualTo(extractedData));
                Assert.That(message, Is.EqualTo(Encoding.UTF8.GetString(extractedData)));
            });
        }

        [Test]
        public void TestEmbedTooLong()
        {
            string message = "Hello, world! This message is a little bit longer then EC group can handle :)";
            byte[] plainData = Encoding.UTF8.GetBytes(message);
            var embedded = _group.EmbedData(plainData);

            var extractedData = embedded.ExtractData();
            Assert.That(message.Substring(0, _group.EmbedLen()) , Is.EqualTo(Encoding.UTF8.GetString(extractedData)));
        }
    }
}