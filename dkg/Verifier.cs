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

namespace dkg
{
    // Verifier receives a Deal from a Dealer, can reply with a Complaint, and can
    // collaborate with other Verifiers to reconstruct a secret.
    public class Verifier: Suite
    {
        public IScalar LongTermKey { get; }
        public IPoint DealerKey { get; }
        public List<IPoint> Verifiers { get; }
        public IPoint PublicKey { get; }
        public int Index { get; }
        public byte[] HkdfContext { get; }
        public Aggregator Aggregator { get; }

        // Constructor returns a Verifier out of:
        //   - its longterm secret key
        //   - the longterm dealer public key
        //   - the list of public key of verifiers. The list MUST include the public key of this Verifier also.
        //
        // The security parameter t of the secret sharing scheme is automatically set to
        // a default safe value. If a different t value is required, it is possible to set
        // it with `verifier.SetT()`.
        public Verifier(IScalar longterm, IPoint dealerKey, List<IPoint> verifiers)
        {
            LongTermKey = longterm;
            DealerKey = dealerKey;
            PublicKey = G.Point().Base().Mul(LongTermKey);
            bool ok = false;
            int index = -1;

            for (int i = 0; i < verifiers.Count; i++)
            {
                if (verifiers[i].Equals(PublicKey))
                {
                    ok = true;
                    index = i;
                    break;
                }
            }
            if (!ok)
            {
                throw new ArgumentException("Verifier: public key not found in the list of verifiers");
            }

            Verifiers = verifiers;
            Index = index;
            HkdfContext = DhHelper.Context(Hash, dealerKey, verifiers);
            Aggregator = new Aggregator(verifiers);
        }

        public (Deal?, string?) DecryptDeal(EncryptedDeal encrypted)
        {
            // verify signature
            var err = Schnorr.Verify(G, DealerKey, encrypted.DHKey, encrypted.Signature);
            if (err != null)
            {
                return (null, err);
            }

            // compute shared key and AES526-GCM cipher
            var dhKey = G.Point();
            dhKey.UnmarshalBinary(new MemoryStream(encrypted.DHKey));
            if (err != null)
            {
                return (null, err);
            }
            var pre = DhHelper.DhExchange(LongTermKey, dhKey);
            var gcm = DhHelper.CreateAEAD(pre, HkdfContext);
            if (err != null)
            {
                return (null, err);
            }

            byte[] decrypted = new byte[encrypted.Cipher.Length];

            gcm.Decrypt(encrypted.Nonce, encrypted.Cipher, encrypted.Tag, decrypted);

            var deal = new Deal();
            deal.UnmarshalBinary(new MemoryStream(decrypted));
            return (deal, err);
        }
    }
}
