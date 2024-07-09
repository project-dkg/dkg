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

using dkg.group;
using Org.BouncyCastle.Crypto.Digests;


namespace dkg.vss
{
    public static class VssTools
    {
        public static byte[] CreateSessionId(IPoint publicKey, IPoint[] verifiers, IPoint[] commitments, int t)
        {
            MemoryStream strm = new();
            publicKey.MarshalBinary(strm);
            foreach (var vrf in verifiers)
            {
                vrf.MarshalBinary(strm);
            }

            foreach (var cmt in commitments)
            {
                cmt.MarshalBinary(strm);
            }
            strm.Write(BitConverter.GetBytes((uint)t));

            // Use BouncyCastle's SHA-256 implementation
            Sha256Digest digest = new();
            byte[] inputBytes = strm.ToArray();
            digest.BlockUpdate(inputBytes, 0, inputBytes.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);

            return result;
        }

        // MinimumT returns a safe value of T that balances secrecy and robustness.
        // It expects n, the total number of participants.
        // T should be adjusted to your threat model. Setting a lower T decreases the
        // difficulty for an adversary to break secrecy. However, a too large T makes
        // it possible for an adversary to prevent recovery (robustness).
        public static int MinimumT(int n)
        {
            return Math.Max((n + 1) / 2, 2);
        }

        public static bool ValidT(int t, IPoint[] verifiers)
        {
            return t >= 2 && t <= verifiers.Length;
        }

        public static IPoint? GetPub(IPoint[] verifiers, int idx)
        {
            if (idx >= verifiers.Length || idx < 0)
            {
                return null;
            }
            return verifiers[idx];
        }

        public static int FindPubIdx(IPoint[] points, IPoint toFind)
        {
            for (int i = 0; i < points.Length; i++)
            {
                if (points[i].Equals(toFind))
                {
                    return i;
                }
            }
            return -1;
        }
    }

}
