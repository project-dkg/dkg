// Copyright (c) 2023 Maxim [maxirmx] Samsonov (https://sw.consulting)
// All rights reserved.
// This file is a part of dkg

using System.Security.Cryptography;

namespace dkg
{
    // Marshalling provides a common implementation of (un)marshalling methods using Stream.
    public static class Marshalling
    {
        // PointMarshalTo provides a generic implementation of Point.EncodeTo
        // based on Point.Encode.
        public static void PointMarshalTo(IPoint p, Stream w)
        {
            p.MarshalBinary(w);
        }

        // PointUnmarshalFrom provides a generic implementation of Point.DecodeFrom,
        // based on Point.Decode, or Point.Pick if r is a CryptoStream.
        // The returned byte-count is valid only when decoding from a normal Reader,
        // not when picking from a pseudorandom source.
        public static void PointUnmarshalFrom(IPoint p, Stream r)
        {
            if (r is RandomStream strm)
            {
                p.Pick(strm);
            }
            else
            {
                p.UnmarshalBinary(r);
            }
        }

        // ScalarMarshalTo provides a generic implementation of Scalar.EncodeTo
        // based on Scalar.Encode.
        public static void ScalarMarshalTo(IScalar s, Stream w)
        {
            s.MarshalBinary(w);
        }

        // ScalarUnmarshalFrom provides a generic implementation of Scalar.DecodeFrom,
        // based on Scalar.Decode, or Scalar.Pick if r is a CryptoStream.
        // The returned byte-count is valid only when decoding from a normal Reader,
        // not when picking from a pseudorandom source.
        public static void ScalarUnmarshalFrom(IScalar s, Stream r)
        {
            if (r is RandomStream strm)
            {
                s.Pick(strm);
            }
            else
            {
                s.UnmarshalBinary(r);
            }
        }

        // GroupNew is the Default implementation of reflective constructor for Group
        public static object? GroupNew(IGroup g, Type t)
        {
            if (t == typeof(IScalar))
            {
                return g.Scalar();
            }
            else if (t == typeof(IPoint))
            {
                return g.Point();
            }
            return null;
        }
    }
}
