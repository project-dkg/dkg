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

//
// Class Schnorr implements the vanilla Schnorr signature scheme.
// See https://en.wikipedia.org/wiki/Schnorr_signature.
//
// The only difference regarding the vanilla reference is the computation of
// the response. This implementation adds the random component with the
// challenge times private key while classical approach substracts them.
//
// The resulting signature shall be  compatible with EdDSA verification algorithm
// when using the edwards25519 group.
//

using System.Security.Cryptography;
using dkg.group;

namespace dkg
{
    public static class Schnorr
    {
        public static byte[] Sign(IGroup g, HashAlgorithm h, IScalar privateKey, byte[] msg)
        {
            // create random secret k and public point commitment R
            var k = g.Scalar();
            var R = g.Base().Mul(k);

            // create hash(publicKey || R || msg)
            var publicKey = g.Base().Mul(privateKey);
            var hash = Hash(g, h, publicKey, R, msg);

            // compute response s = k + x*h
            var s = k.Add(privateKey.Mul(hash));

            // return R || S

            var b = new MemoryStream();
            R.MarshalBinary(b);
            s.MarshalBinary(b);
            return b.ToArray();
        }

        public static void Verify(IGroup g, HashAlgorithm h, IPoint publicKey, byte[] msg, byte[] sig)
        {
            const string invalidLength = "Invalid length";
            const string invalidSignature = "Invalid signature";

            var R = g.Point();
            var s = g.Scalar();
            using (var memstream = new MemoryStream(sig))
            {
                try
                {
                    R.UnmarshalBinary(memstream);
                    s.UnmarshalBinary(memstream);
                    if (memstream.Position != memstream.Length)
                    // Extra bytes in signature are not acceptable
                    {
                        throw new DkgError(invalidLength, "Schnorr");
                    }
                }
                catch
                // May be System.IO.EndOfStreamException
                // but also can fail during decoding if some constraints are not met
                {
                    throw new DkgError(invalidLength, "Schnorr");
                }
            }

            // recompute hash(publicKey || R || msg)
            var hash = Hash(g, h, publicKey, R, msg);

            // compute S = g^s
            var S = g.Base().Mul(s);
            // compute RAh = R + A^h
            var Ah = publicKey.Mul(hash);
            var RAs = R.Add(Ah);

            if (!S.Equals(RAs))
            {
                throw new DkgError(invalidSignature, "Schnorr");
            }
        }

        private static IScalar Hash(IGroup g, HashAlgorithm h, IPoint publicPoint, IPoint r, byte[] msg)
        {
            var b = new MemoryStream();
            r.MarshalBinary(b);
            publicPoint.MarshalBinary(b);
            BinaryWriter w = new(b);
            w.Write(msg);
            var hash = h.ComputeHash(b.ToArray());
            return g.Scalar().SetBytes(hash);
        }
    }
}
