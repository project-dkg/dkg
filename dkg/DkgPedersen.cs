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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters; 

using System.Security.Cryptography;
using System.Text;


namespace dkg
{
    public static class DhHelper
    {
        public const int sharedKeySize = 32;
        public const int nonceSizeInBytes = 12;
        public const int tagSizeInBytes = 16;

        // dhExchange computes the shared key from a private key and a public key
        public static IPoint DhExchange(IScalar ownPrivate, IPoint remotePublic)
        {
            return remotePublic.Mul(ownPrivate);
        }

        // CreateAEAD returns the AEAD cipher to be used to encrypt a share
        public static AesGcm CreateAEAD(IPoint preSharedKey, byte[] hkdfContext)
        {
            var sharedKey = CreateHKDF(preSharedKey.GetBytes(), hkdfContext);
            var aes = Aes.Create();
            aes.Key = sharedKey;
            return new AesGcm(aes.Key, tagSizeInBytes);
        }

        public static byte[] CreateHKDF(byte[] preSharedKey, byte[] hkdfContext)
        {
            // Create HKDF generator
            HkdfBytesGenerator hkdf = new(new Sha256Digest());

            // Initialize generator
            hkdf.Init(new HkdfParameters(preSharedKey, hkdfContext, null));

            // Generate shared key
            byte[] sharedKey = new byte[sharedKeySize];
            hkdf.GenerateBytes(sharedKey, 0, sharedKeySize);

            return sharedKey;
        }


        // Context returns the context slice to be used when encrypting a share
        public static byte[] Context(HashAlgorithm hash, IPoint publicKey, IPoint[] verifiers)
        {
            MemoryStream strm = new();
            strm.Write(Encoding.UTF8.GetBytes("dkg-dealer"));
            publicKey.MarshalBinary(strm);
            strm.Write(Encoding.UTF8.GetBytes("dkg-verifiers"));
            foreach (var vrf in verifiers)
            {
                vrf.MarshalBinary(strm);
            }
            return hash.ComputeHash(strm.ToArray());
        }
    }


    public class XOFHelper
    {
        private const int _keySize = 128;
        private const int _digestSize = 256;
        private readonly ShakeDigest shake = new(_digestSize);
        public byte[] XOF(byte[] data)
        {
            shake.BlockUpdate(data, 0, data.Length);
            var result = new byte[_keySize];
            shake.DoFinal(result, 0);
            return result;
        }
    }

    public class HkdfHelper
    {
        private const int _keySize = 32;
        HkdfBytesGenerator hkdf;
        public HkdfHelper(byte[] context) 
        {
            hkdf = new HkdfBytesGenerator(new Sha256Digest());

        }
    }
    public static class Suite
    {
        public static readonly IGroup G = new Secp256k1Group();
        public static readonly HashAlgorithm Hash = SHA256.Create();
    }

    public static class Tools
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
            return Suite.Hash.ComputeHash(strm.ToArray());
        }

        // MinimumT returns a safe value of T that balances secrecy and robustness.
        // It expects n, the total number of participants.
        // T should be adjusted to your threat model. Setting a lower T decreases the
        // difficulty for an adversary to break secrecy. However, a too large T makes
        // it possible for an adversary to prevent recovery (robustness).
        public static int MinimumT(int n)
        {
            return (n + 1) / 2;
        }

        public static bool ValidT(int t, IPoint[] verifiers)
        {
            return t >= 2 && t <= verifiers.Length;
        }

        public static IPoint? FindPub(IPoint[] verifiers, int idx)
        {
            if (idx >= verifiers.Length || idx < 0)
            {
                return null;
            }
            return verifiers[idx];
        }
    }

    // Dealer encapsulates for creating and distributing the shares and for
    // replying to any Responses.
    public class Dealer
    {

        private readonly XOFHelper xof;
        public Stream Reader { get; set; }
        public IScalar LongTermKey { get; set; }
        public IPoint PublicKey { get; set; }
        public IScalar Secret { get; set; }
        public IPoint[] Verifiers { get; set; }
        public List<IPoint> SecretCommits { get; set; }
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
        public Dealer(IScalar longterm, IScalar secret, IPoint[] verifiers, int t)
        {
            if (!Tools.ValidT(t, verifiers))
            {
                throw new ArgumentException($"Dealer: t {t} invalid");
            }

            xof = new XOFHelper();
            
            LongTermKey = longterm;
            Secret = secret;
            Verifiers = verifiers;
            T = t;

            var f = new PriPoly(Suite.G, T, Secret);
            PublicKey = Suite.G.Point().Base().Mul(LongTermKey);

            // Compute public polynomial coefficients
            var F = f.Commit(Suite.G.Point().Base());
            //SecretCommits = [.. F.Commits];

            SessionId = Tools.CreateSessionId(PublicKey, Verifiers, F.Commits, T);

            Aggregator = new Aggregator(PublicKey, Verifiers, F.Commits, T, SessionId);
            // C = F + G
            Deals = new Deal[Verifiers.Length];
            for (int i = 0; i < Verifiers.Length; i++)
            {
                var fi = f.Eval(i);
                Deals[i] = new Deal(SessionId, fi, F.Commits, T);
            }
            HkdfContext = DhHelper.Context(Suite.Hash, PublicKey, Verifiers);
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
            IPoint vPub = Tools.FindPub(Verifiers, i) ?? throw new Exception("EncryptedDeal: verifier index is out of range"); 
            // gen ephemeral key
            var dhSecret = Suite.G.Scalar();
            var dhPublic = Suite.G.Point().Base().Mul(dhSecret);
            // signs the public key
            var dhPublicBuff = dhPublic.GetBytes();
            var signature = Schnorr.Sign(LongTermKey, dhPublicBuff) ?? throw new Exception("EncryptedDeal: error signing the public key");

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
        // so each DKG node can still compute its share if enough Deals are valid.
        public void SetTimeout()
        {
            Aggregator.Timeout = true;
        }

        // ProcessResponse analyzes the given Response. If it's a valid complaint, then
        // it returns a Justification. This Justification must be broadcasted to every
        // participants. If it's an invalid complaint, it returns an error about the
        // complaint. The verifiers will also ignore an invalid Complaint.
        /*  public Justification? ProcessResponse(Response r)
          {
              Aggregator.VerifyResponse(r);
              if (r.Status == Status.Approval)
              {
                  return null;
              }

              var j = new Justification
              {
                  SessionId = SessionId,
                  // index is guaranteed to be good because of VerifyResponse before
                  Index = r.Index,
                  Deal = Deals[(int)r.Index],
              };
              var (sig, err) = Schnorr.Sign(g, LongTermKey, hash);
              if (err != null)
              {
                  return (null, err);
              }
              j.Signature = sig;
              return j;
          }
        */
    }

 
    public class Justification
    {
        // SessionId related to the current run of the protocol
        public byte[] SessionId { get; set; }

        // Index of the verifier who issued the Complaint,i.e. index of this Deal
        public uint Index { get; set; }

        // Deal in cleartext
        public Deal Deal { get; set; }

        // Signature over the whole packet
        public byte[] Signature { get; set; }
    }

}
