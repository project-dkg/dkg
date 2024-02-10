// Copyright (c) 2023 Maxim [maxirmx] Samsonov (https://sw.consulting)
// All rights reserved.
// This file is a part of dkg

namespace dkg
{
    public interface IMarshalling
    {
        public void MarshalBinary(Stream s);
        public Int32 MarshalSize();
        public void UnmarshalBinary(Stream s);
    }

    // Scalar represents a scalar value by which
    // a Point (group element) may be encrypted to produce another Point.
    // This is an exponent in DSA-style groups,
    // in which security is based on the Discrete Logarithm assumption,
    // and a scalar multiplier in elliptic curve groups.

    public interface IScalar : IMarshalling, IEquatable<IScalar>
    {
        // Set sets the receiver equal to another Scalar a.
        IScalar Set(IScalar s2);
        // Clone creates a new Scalar with the same value.
        IScalar Clone();
        // SetInt64 sets the receiver to a small integer value.
        IScalar SetInt64(Int64 v);
        // Set to the additive identity (0).
        IScalar Zero();
        // Modular sum of this and s2.
        IScalar Add(IScalar b);
        // Modular differenceb.
        IScalar Sub(IScalar b);
        // Set to the modular negation of scalar.
        IScalar Neg();
        // Set to the multiplicative identity (1).
        IScalar One();
        // Set to the modular product of scalars
        IScalar Mul(IScalar b);
        // Set to the modular division of scalars
        IScalar Div(IScalar b);
        // Set to the modular inverse of scalar.
        IScalar Inv();
        // Set to a fresh random or pseudo-random scalar.
        IScalar Pick(RandomStream strm);
        // SetBytes sets the scalar from a byte-slice,
        // reducing if necessary to the appropriate modulus.
        // The endianess of the byte-slice is determined by the
        // implementation.
        IScalar SetBytes(byte[] bytes);
        // GetBytes returns the byte-slice representation of the scalar.
        // The endianess of the byte-slice is determined by the
        // implementation.
        byte[] GetBytes();
    }

    // Point represents an element of a public-key cryptographic Group.
    // For example,
    // this is a number modulo the prime P in a DSA-style Schnorr group,
    // or an (x, y) point on an elliptic curve.
    // A Point can contain a Diffie-Hellman public key, an ElGamal ciphertext, etc.
    public interface IPoint : IMarshalling, IEquatable<IPoint>
    {
        // Null sets the receiver to the neutral identity element.
        IPoint Null();
        // Base sets the receiver to this group's standard base point.
        IPoint Base();
        // Pick sets the receiver to a fresh random or pseudo-random Point.
        IPoint Pick(RandomStream strm);
        // Set sets the receiver equal to another Point p.
        IPoint Set(IPoint p);
        // Clone clones the underlying point.
        IPoint Clone();
        // Add points so that their scalars add homomorphically.
        IPoint Add(IPoint s2);
        // Subtract points so that their scalars subtract homomorphically.
        IPoint Sub(IPoint b);
        // Set to the negation of point.
        IPoint Neg();
        // Multiply point by the scalar s.
        IPoint Mul(IScalar s);
        byte[] GetBytes();
    }

    // AllowsVarTime allows callers to determine if a given kyber.Scalar
    // or kyber.Point supports opting-in to variable time operations. If
    // an object implements AllowsVarTime, then the caller can use
    // AllowVarTime(true) in order to allow variable time operations on
    // that object until AllowVarTime(false) is called. Variable time
    // operations may be faster, but also risk leaking information via a
    // timing side channel. Thus they are only safe to use on public
    // Scalars and Points, never on secret ones.
    public interface IAllowsVarTime
    {
        void AllowVarTime(bool allow);
    }

    // Group interface represents a mathematical group
    // usable for Diffie-Hellman key exchange, ElGamal encryption,
    // and the related body of public-key cryptographic algorithms
    // and zero-knowledge proof methods.
    // The Group interface is designed in particular to be a generic front-end
    // to both traditional DSA-style modular arithmetic groups
    // and ECDSA-style elliptic curves:
    // the caller of this interface's methods
    // need not know or care which specific mathematical construction
    // underlies the interface.
    //
    // The Group interface is essentially just a "constructor" interface
    // enabling the caller to generate the two particular types of objects
    // relevant to DSA-style public-key cryptography;
    // we call these objects Points and Scalars.
    // The caller must explicitly initialize or set a new Point or Scalar object
    // to some value before using it as an input to some other operation
    // involving Point and/or Scalar objects.
    // For example, to compare a point P against the neutral (identity) element,
    // you might use P.Equals(suite.Point().Null()),
    // but not just P.Equals(suite.Point()).
    //
    // It is expected that any implementation of this interface
    // should satisfy suitable hardness assumptions for the applicable group:
    // e.g., that it is cryptographically hard for an adversary to
    // take an encrypted Point and the known generator it was based on,
    // and derive the Scalar with which the Point was encrypted.
    // Any implementation is also expected to satisfy
    // the standard homomorphism properties that Diffie-Hellman
    // and the associated body of public-key cryptography are based on.
    public interface IGroup
    {
        // Max length of scalars in bytes
        string ToString();
        
        // Max length of scalars in bytes
        int ScalarLen();
        // Create new scalar
        IScalar Scalar();
        // Max length of point in bytes
        int PointLen();
        // Create new point
        IPoint Point();
    }
}
