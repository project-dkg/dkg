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

using dkg.util;
using dkg.group;
using dkg.poly;

using HashAlgorithm = System.Security.Cryptography.HashAlgorithm;

namespace dkg.vss
{
    // Dealer encapsulates for creating and distributing the shares and for
    // replying to any Responses.
    public class Dealer
    {
        private HashAlgorithm Hash { get; }
        public IScalar LongTermKey { get; set; }
        public IPoint PublicKey { get; set; }
        public IScalar Secret { get; set; }
        public IPoint[] Verifiers { get; set; }
        public PriPoly SecretPoly { get; set; }
        public byte[] HkdfContext { get; set; }
        public int T { get; set; }
        public byte[] SessionId { get; set; }
        public Deal[] Deals { get; set; }
        public Aggregator Aggregator { get; set; }

        // NewDealer returns a Dealer capable of leading the secret sharing scheme. It
        // does not have to be trusted by other Verifiers. The security parameter t is
        // the number of shares required to reconstruct the secret. MinimumT() provides
        // a middle ground between robustness and secrecy. Increasing t will increase
        // the secrecy at the cost of the decreased robustness and vice versa. It 
        // returns an error if the t is inferior or equal to 2.
        public Dealer(HashAlgorithm hash, IScalar longterm, IScalar secret, IPoint[] verifiers, int t)
        {
            if (!VssTools.ValidT(t, verifiers))
            {
                throw new ArgumentException($"Dealer: Threshold value {t} is invalid");
            }
            Hash = hash;
            LongTermKey = longterm;
            Secret = secret;
            Verifiers = verifiers;
            T = t;

            var f = new PriPoly(Suite.G, T, Secret);
            PublicKey = Suite.G.Base().Mul(LongTermKey);

            // Compute public polynomial coefficients
            var F = f.Commit(Suite.G.Base());

            SessionId = VssTools.CreateSessionId(Hash, PublicKey, Verifiers, F.Commits, T);

            Aggregator = new Aggregator(Hash, PublicKey, Verifiers, F.Commits, T, SessionId);
            // C = F + G
            Deals = new Deal[Verifiers.Length];
            for (int i = 0; i < Verifiers.Length; i++)
            {
                var fi = f.Eval(i);
                Deals[i] = new Deal(SessionId, fi, F.Commits, T);
            }
            HkdfContext = DhHelper.Context(Hash, PublicKey, Verifiers);
            SecretPoly = f;
        }

        // PlaintextDeal returns the plaintext version of the deal destined for peer i.
        // Use this only for testing.
        public Deal PlaintextDeal(int i)
        {
            if (i >= Deals.Length || i < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(i));
            }
            return Deals[i];
        }

        // EncryptedDeal returns the encryption of the deal that must be given to the
        // verifier at index i.
        public EncryptedDeal EncryptedDeal(int i)
        {
            IPoint vPub = VssTools.GetPub(Verifiers, i) ?? throw new Exception("EncryptedDeal: verifier index is out of range");
            // gen ephemeral key
            var dhSecret = Suite.G.Scalar();
            var dhPublic = Suite.G.Base().Mul(dhSecret);
            // signs the public key
            var dhPublicBuff = dhPublic.GetBytes();
            var signature = Schnorr.Sign(Suite.G, Hash, LongTermKey, dhPublicBuff) ?? throw new Exception("EncryptedDeal: error signing the public key");

            // AES128-GCM
            var pre = DhHelper.DhExchange(dhSecret, vPub);
            var gcm = DhHelper.CreateAEAD(pre, HkdfContext) ?? throw new Exception("EncryptedDeal: error creating new AEAD");
            var nonce = new byte[DhHelper.nonceSizeInBytes];

            var deal = Deals[i].GetBytes();
            byte[] encrypted = new byte[deal.Length];
            byte[] tag = new byte[gcm.TagSizeInBytes ?? 16];
            gcm.Encrypt(nonce, deal, encrypted, tag);

            return new EncryptedDeal(dhPublicBuff, signature, nonce, encrypted, tag);
        }

        // EncryptedDeals calls `EncryptedDeal` for each index of the verifier and
        // returns the list of encrypted deals. Each index in the returned list
        // corresponds to the index in the list of verifiers.
        public EncryptedDeal[] EncryptedDeals()
        {
            var deals = new EncryptedDeal[Verifiers.Length];
            for (int i = 0; i < Verifiers.Length; i++)
            {
                deals[i] = EncryptedDeal(i);
            }
            return deals;
        }

        // SetTimeout marks the end of a round, invalidating any missing (or future) response
        // for this DKG protocol round. The caller is expected to call this after a long timeout
        // so each DKG node can still compute its share if enough GetDistDeals are valid.
        public void SetTimeout()
        {
            Aggregator.Timeout = true;
        }

        // SecretCommit returns the commitment of the secret being shared by this
        // dealer. This function is only to be called once the deal has enough approvals
        // and is verified otherwise it returns nil.
        public IPoint? SecretCommit()
        {
            if (!Aggregator.DealCertified())
            {
                return null;
            }
            return Suite.G.Base().Mul(Secret);
        }


        // ProcessResponse analyzes the given Response. If it's a valid complaint, then
        // it returns a Justification. This Justification must be broadcasted to every
        // participants. If it's an invalid complaint, it returns an error about the
        // complaint. The verifiers will also ignore an invalid Complaint.
        public Justification? ProcessResponse(Response r)
        {
            Aggregator.VerifyResponse(r);
            if (r.Status == ResponseStatus.Approval)
                return null;

            var j = new Justification(SessionId, r.Index, Deals[r.Index]);
            j.Signature = Schnorr.Sign(Suite.G, Hash,  LongTermKey, j.GetBytesForSignature());
            return j;
        }
        // RecoverSecret recovers the secret shared by a Dealer by gathering at least t
        // GetDistDeals from the verifiers. It returns an error if there is not enough GetDistDeals or
        // if all GetDistDeals don't have the same SessionID.
        public static IScalar RecoverSecret(Deal[] deals, int n, int t)
        {
            PriShare[] shares = new PriShare[deals.Length];
            for (int i = 0; i < deals.Length; i++)
            {
                // all sids the same
                if (deals[i].SessionId.SequenceEqual(deals[0].SessionId))
                {
                    shares[i] = deals[i].SecShare;
                }
                else
                {
                    throw new DkgError("All deals need to have same session id", "RecoverSecret");
                }
            }
            return PriPoly.RecoverSecret(Suite.G, shares, t, n);
        }
    }
}
