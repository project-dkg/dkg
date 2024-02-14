using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace dkg
{
    public class Secp256k1Scalar : IScalar, IEquatable<Secp256k1Scalar>
    {
        private BigInteger _value;
        private static readonly X9ECParameters _ecP = ECNamedCurveTable.GetByName("secp256k1");
        private static readonly BigInteger _order = _ecP.N;
        private static readonly int _length = (_order.BitLength + 7) / 8;

        // GetHashCode() is overridden to ensure that instances of Secp256k1Scalar that are equal
        // (according to the Equals method) return the same hash code.
        // This is important for correct behavior in collections.

        public Secp256k1Scalar()
        {
            _value = BigInteger.Zero;
        }
        public Secp256k1Scalar (BigInteger value)
        {
            _value = value;
        }
        public override bool Equals(object? obj)
        {
            return Equals(obj as Secp256k1Scalar);
        }

        public BigInteger GetValue()
        {
            return _value;
        }
        public int GetLength()
        {
            return _length;
        }
        public override int GetHashCode()
        {
            return _value.GetHashCode();
        }
        public override string ToString()
        {
            return $"{{Secp256k1 Scalar: Value = {_value}}}";
        }
        public bool Equals(Secp256k1Scalar? other)
        {
            if (other == null)
                return false;

            return _value.Equals(other._value);
        }
        public bool Equals(IScalar? s2)
        {
            Secp256k1Scalar? other = s2 as Secp256k1Scalar;
            return Equals(other);
        }

        public IScalar Set(IScalar? s2)
        {
            if (s2 is not Secp256k1Scalar other)
                throw new InvalidCastException("s2 is not a Secp256k1Scalar");
            _value = other._value;
            return this;
        }

        public IScalar Clone()
        {
            return new Secp256k1Scalar(_value);
        }

        public IScalar SetInt64(Int64 v)
        {
            _value = new BigInteger(v.ToString());
            return this;
        }

        public IScalar Zero()
        {
            _value = BigInteger.Zero;
            return this;
        }   

        public IScalar Add(IScalar s2)
        {
            if (s2 is not Secp256k1Scalar other2)
                throw new InvalidCastException("s2 is not a Secp256k1Scalar");

            return new Secp256k1Scalar(_value.Add(other2._value).Mod(_order));
        }

        public IScalar Sub(IScalar s2)
        {
            if (s2 is not Secp256k1Scalar other2)
                throw new InvalidCastException("s2 is not a Secp256k1Scalar");

            return new Secp256k1Scalar(_value.Subtract(other2._value).Mod(_order));
        }

        public IScalar Neg()
        {
            return new Secp256k1Scalar(_value.Negate().Mod(_order));
        }

        public IScalar One()
        {
            _value = BigInteger.One;
            return this;
        }

        public IScalar Mul(IScalar s2)
        {
            if (s2 is not Secp256k1Scalar other2)
                throw new InvalidCastException("s2 is not a Secp256k1Scalar");

            return new Secp256k1Scalar(_value.ModMultiply(other2._value, _order));
        }

        public IScalar Div(IScalar s2)
        {
            if (s2 is not Secp256k1Scalar other2)
                throw new InvalidCastException("s2 is not a Secp256k1Scalar");

            return new Secp256k1Scalar(_value.ModDivide(other2._value, _order));
        }

        public IScalar Inv()
        {
            return new Secp256k1Scalar(_value.ModInverse(_order));
        }

        public IScalar Pick(RandomStream strm)
        {
            BinaryReader reader = new(strm);
            byte[] bytes = reader.ReadBytes(_length);
            _value = new BigInteger(bytes).Mod(_order);
            return this;
        }

        public IScalar SetBytes(byte[] bytes)
        {
            _value = new BigInteger(bytes).Mod(_order);
            return this;
        }

        public byte[] GetBytes()
        {
            return _value.ToByteArray();
        }

        public void MarshalBinary(Stream s)
        {
            byte[] bytes = GetBytes();
            BinaryWriter writer = new(s);
            writer.Write(bytes.Length);
            writer.Write(bytes);
        }

        public int MarshalSize()
        {
            return GetBytes().Length + sizeof(Int32);
        }

        public void UnmarshalBinary(Stream s)
        {
            BinaryReader reader = new(s);
            Int32 length = reader.ReadInt32();
            byte[] bytes = reader.ReadBytes(length);
            SetBytes(bytes);
        }
    }

    public class Secp256k1Point : IPoint, IEquatable<Secp256k1Point>
    {
        private ECPoint _point;
        private static readonly X9ECParameters _ecP = ECNamedCurveTable.GetByName("secp256k1");
        private static readonly ECCurve _curve = _ecP.Curve;

        public Secp256k1Point()
        {
            _point = _ecP.G.Multiply(BigInteger.Zero);
        }

        public Secp256k1Point(ECPoint point)
        {
            _point = point;
        }
        public override string ToString()
        {
            return $"{{Secp256k1 Point: X = {_point.AffineXCoord}, Y = {_point.AffineYCoord}}}";
        }
        public override int GetHashCode()
        {
            unchecked // Overflow is fine, just wrap
            {
                int hash = 17;
                hash = hash * 31 + _point.AffineXCoord.GetHashCode();
                hash = hash * 31 + _point.AffineYCoord.GetHashCode();
                return hash;
            }
        }
        public override bool Equals(object? obj)
        {
            return Equals(obj as Secp256k1Point);
        }

        public bool Equals(Secp256k1Point? other)
        {
            if (other == null)
                return false;

            return _point.Equals(other._point);
        }

        public bool Equals(IPoint? p2)
        {
            Secp256k1Point? other = p2 as Secp256k1Point;
            return Equals(other);
        }

        public static int GetLength()
        {
            return 33; // for compressed form
        }

        public IPoint Null()
        {
            _point = _ecP.G.Multiply(BigInteger.Zero);
            return this;
        }

        public IPoint Base()
        {
            _point = _ecP.G;
            return this;
        }

        public IPoint Pick(RandomStream strm)
        {
            Secp256k1Scalar randomScalar = new();
            randomScalar.Pick(strm);
            _point = _ecP.G.Multiply(randomScalar.GetValue());
            return this;
        }

        public IPoint Set(IPoint p2)
        {
            if (p2 is not Secp256k1Point other2)
                throw new InvalidCastException("p2 is not a Secp256k1Point");
            _point = other2._point;
            return this;
        }

        public IPoint Clone()
        {
            return new Secp256k1Point(_point);
        }

        public IPoint Add(IPoint s2)
        {
            if (s2 is not Secp256k1Point other2)
                throw new InvalidCastException("s2 is not a Secp256k1Point");

            ECPoint resultPoint = _point.Add(other2._point);
            return new Secp256k1Point(resultPoint);
        }
        public IPoint Sub(IPoint s2)
        {
            if (s2 is not Secp256k1Point other2)
                throw new InvalidCastException("s2 is not a Secp256k1Point");

            // Subtracting points in elliptic curves is equivalent to adding the first point to the negation of the second point
            ECPoint resultPoint = _point.Add(other2._point.Negate());
            return new Secp256k1Point(resultPoint);
        }

        public IPoint Neg()
        {
            ECPoint resultPoint = _point.Negate();
            return new Secp256k1Point(resultPoint);
        }

        public IPoint Mul(IScalar s)
        {
            if (s is not Secp256k1Scalar scalar)
                throw new InvalidCastException("s is not a Secp256k1Scalar");

            ECPoint resultPoint = _point.Multiply(scalar.GetValue());
            return new Secp256k1Point(resultPoint);
        }

        public void MarshalBinary(Stream s)
        {
            byte[] bytes = _point.GetEncoded(true); // true for compressed form
            s.Write(bytes, 0, bytes.Length);
        }

        public int MarshalSize()
        {
            return GetLength();
        }

        public void UnmarshalBinary(Stream s)
        {
            byte[] bytes = new byte[GetLength()]; // 33 bytes for a compressed point
            s.Read(bytes, 0, bytes.Length);
            _point = _ecP.Curve.DecodePoint(bytes);
        }

        public byte[] GetBytes()
        {
            return _point.GetEncoded(true); // true for compressed form
        }
    }

    public class Secp256k1Group : IGroup, IEquatable<Secp256k1Group>
    {
        private static readonly X9ECParameters _ecP = ECNamedCurveTable.GetByName("secp256k1");
        private static readonly ECCurve _curve = _ecP.Curve;

        private readonly RandomStream strm = new();
        public override bool Equals(object? obj)
        {
            return Equals(obj as Secp256k1Group);
        }

        public bool Equals(Secp256k1Group? other)
        {
            // All instances of Secp256k1Group are equal, because they represent the same mathematical group.
            // So, if the other object is a Secp256k1Group, we return true.
            // If it's null or a different type, we return false.
            return other is not null;
        }
        public override int GetHashCode()
        {
            // All instances of Secp256k1Group are equal, so they should return the same hash code.
            // We can just return a constant value.
            return ToString().GetHashCode();
        }
        public override string ToString()
        {
            return $"Secp256k1 Group: Order = {_ecP.N}, Scalar Length = {ScalarLen()}, Point Length = {PointLen()}";
        }
        public int ScalarLen()
        {
            return new Secp256k1Scalar().GetLength();
        }

        public IScalar Scalar()
        {
            return new Secp256k1Scalar().Pick(strm);
        }

        public int PointLen()
        {
            return Secp256k1Point.GetLength();
        }

        public IPoint Point()
        {
            return new Secp256k1Point().Pick(strm);
        }

        public RandomStream RndStream()
        {
            return strm;
        }
    }
}
