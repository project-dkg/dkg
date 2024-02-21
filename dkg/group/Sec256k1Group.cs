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

// Group implementation based on BouncyCastle secp256k1

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using System.Security.Cryptography;

using ECPoint = Org.BouncyCastle.Math.EC.ECPoint;
using ECCurve = Org.BouncyCastle.Math.EC.ECCurve;

namespace dkg.group
{
    public class Secp256k1Scalar : IScalar, IEquatable<Secp256k1Scalar>
    {
        public BigInteger _value;
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
        public Secp256k1Scalar(BigInteger value)
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
            return $"{{Secp256k1 Scalar: {_value}}}";
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

        public IScalar SetInt64(long v)
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

        public IScalar Mod(IScalar s2)
        {
            if (s2 is not Secp256k1Scalar other2)
                throw new InvalidCastException("s2 is not a Secp256k1Scalar");

            return new Secp256k1Scalar(_value.Mod(other2._value).Mod(_order));
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
            _value = new BigInteger(1, bytes).Mod(_order);
            return this;
        }

        public byte[] GetBytes()
        {
            byte[] bytes = _value.ToByteArrayUnsigned();

            if (bytes.Length < _length)
            {
                byte[] paddedBytes = new byte[_length];
                Array.Copy(bytes, 0, paddedBytes, _length - bytes.Length, bytes.Length); // Copy bytes to the end of paddedBytes
                bytes = paddedBytes;
            }
            else if (bytes.Length > _length)
            {
                throw new InvalidOperationException("GetBytes: The byte array is longer than expected.");
            }

            return bytes;
        }
        public void MarshalBinary(Stream s)
        {
            byte[] bytes = GetBytes();
            BinaryWriter writer = new(s);
            writer.Write(bytes);
        }

        public int MarshalSize()
        {
            return GetLength();
        }

        public void UnmarshalBinary(Stream s)
        {
            BinaryReader reader = new(s);
            byte[] bytes = reader.ReadBytes(GetLength());
            SetBytes(bytes);
        }
    }

    public class Secp256k1Point : IPoint, IEquatable<Secp256k1Point>
    {
        public ECPoint _point;
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
            return $"{{Secp256k1 Point: {_point.ToString()}}}";
        }
        public override int GetHashCode()
        {
            return _point.GetHashCode();
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

        internal Secp256k1Point Mul(BigInteger i)
        {
            ECPoint resultPoint = _point.Multiply(i);
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

        public bool IsInSubgroup()
        {
            // Multiply the point by the order of the subgroup
            ECPoint result = _point.Multiply(_ecP.N);

            // Check if the result is the point at infinity
            return result.IsInfinity;
        }

        public byte[] ExtractData()
        {
            // Normalize the point to ensure that the coordinates are in the correct form
            _point = _point.Normalize();

            // Convert the x-coordinate to a byte array
            byte[] data = _point.AffineXCoord.ToBigInteger().ToByteArray();

            // Extract the data length from the first byte
            int dataLength = data[0];

            // Check if the data length is valid
            if (dataLength < 1 || dataLength > Secp256k1Group.SEmbedLen())
            {
                throw new ArgumentException("Invalid data length");
            }

            // Create a byte array to hold the message
            byte[] message = new byte[dataLength];

            // Copy the message from the data array
            Buffer.BlockCopy(data, 1, message, 0, dataLength);

            return message;
        }

    }

    public class Secp256k1Group : IGroup, IEquatable<Secp256k1Group>
    {
        private static readonly X9ECParameters _ecP = ECNamedCurveTable.GetByName("secp256k1");
        private static readonly Org.BouncyCastle.Math.EC.ECCurve _curve = _ecP.Curve;

        private readonly RandomStream _strm = new();
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
        public static int SScalarLen()
        {
            return new Secp256k1Scalar().GetLength();
        }
        public int ScalarLen()
        {
            return SScalarLen();
        }

        public IScalar Scalar()
        {
            return new Secp256k1Scalar().Pick(_strm);
        }

        public int PointLen()
        {
            return Secp256k1Point.GetLength();
        }

        public IPoint Point()
        {
            return new Secp256k1Point().Pick(_strm);
        }

        public IPoint Base()
        {
            return new Secp256k1Point().Base();
        }
        public RandomStream RndStream()
        {
            return _strm;
        }

        // Return number of bytes that can be embedded into points on this curve.
        public static int SEmbedLen()
        {
            // Reserve at least 8 most-significant bits for randomness,
            // and the least-significant 8 bits for embedded data length.
            // (Hopefully it's unlikely we'll need >=2048-bit curves soon.)
            return (SScalarLen() - 1 - 1);
        }

        public int EmbedLen()
        {
            return SEmbedLen();
        }

        public IPoint EmbedData(byte[] message)
        {
            // Check if the message is null or empty
            if (message == null || message.Length == 0)
            {
                throw new ArgumentException(nameof(message), "EmbedMessage: Message cannot be null or empty");
            }

            int dataLength = Math.Min(message.Length, EmbedLen());

            // Create a byte array to hold the length byte and the message
            byte[] data = new byte[ScalarLen()];

            // Store the message length in the first byte
            data[0] = (byte)dataLength;


            BigInteger x = BigInteger.Zero, y = BigInteger.Zero;

            const int maxIterations = 256; // Maximum number of iterations
            int iterations = 0; // Current number of iterations

            while (iterations < maxIterations)
            {
                // Fill with random data
                _strm.Read(data, 0, data.Length);
                // Store the message length in the first byte
                data[0] = (byte)dataLength;
                // Copy the message into the rest of the array
                Buffer.BlockCopy(message, 0, data, 1, dataLength);

                // Convert the data to a BigInteger
                x = new BigInteger(1, data);

                ECFieldElement rhs = _ecP.Curve.FromBigInteger(x).Square().Add(_ecP.Curve.A).Multiply(_ecP.Curve.FromBigInteger(x)).Add(_ecP.Curve.B);
                if (rhs.Sqrt() != null)
                {
                    y = rhs.Sqrt().ToBigInteger();
                    break;
                }

                iterations++;
            }

            // If the maximum number of iterations has been reached, throw an exception
            if (iterations >= maxIterations)
            {
                throw new InvalidOperationException("EmbedMessage: Could not find valid point to store a message");
            }

            // Create a point with these coordinates
            ECPoint point = _ecP.Curve.CreatePoint(x, y);
            Secp256k1Point res = new(point);

            // Ensure the point is in the correct subgroup
            if (!res.IsInSubgroup())
            {
                res = res.Mul(_ecP.Curve.Cofactor);
            }

            return res;

        }
    }
}
