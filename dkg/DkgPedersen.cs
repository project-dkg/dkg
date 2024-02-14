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

using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;
using System.Text;


namespace dkg
{
    public enum Status
    {
        // StatusComplaint is a constant value meaning that a verifier issues
        // a Complaint against its Dealer.
        Complaint = 0,
        // StatusApproval is a constant value meaning that a verifier agrees with
        // the share it received.
        Approval = 1
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

    public class Verifiable(List<IPoint> verifiers)
    {
        public List<IPoint> Verifiers { get; set; } = verifiers;

        public IPoint FindPub(int idx)
        {
            if (idx >= Verifiers.Count || idx < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(idx));
            }
            return Verifiers[idx];
        }

    }

    // Dealer encapsulates for creating and distributing the shares and for
    // replying to any Responses.
    public class Dealer : Verifiable
    {
        private readonly IGroup g;
        private readonly XOFHelper xof;
        private readonly HashAlgorithm hash;
        public Stream Reader { get; set; }
        public IScalar LongTermKey { get; set; }
        public IPoint Pub { get; set; }
        public IScalar Secret { get; set; }
        public List<IPoint> SecretCommits { get; set; }
        public PriPoly SecretPoly { get; set; }
        public byte[] HkdfContext { get; set; }
        public int T { get; set; }
        public byte[] SessionId { get; set; }
        public List<Deal> Deals { get; set; }
        public Aggregator Aggregator { get; set; }

        // NewDealer returns a Dealer capable of leading the secret sharing scheme. It
        // does not have to be trusted by other Verifiers. The security parameter t is
        // the number of shares required to reconstruct the secret. MinimumT() provides
        // a middle ground between robustness and secrecy. Increasing t will increase
        // the secrecy at the cost of the decreased robustness and vice versa. It 
        // returns an error if the t is inferior or equal to 2.
        public Dealer(IGroup group, IScalar longterm, IScalar secret, List<IPoint> verifiers, int t) :
            base(verifiers)
        {
            if (!ValidT(t, verifiers))
            {
                throw new ArgumentException($"Dealer: t {t} invalid");
            }

            g = group;
            xof = new XOFHelper();
            hash = SHA256.Create();

            LongTermKey = longterm;
            Secret = secret;
            T = t;

            var f = new PriPoly(g, T, Secret);
            Pub = g.Point().Base().Mul(LongTermKey);

            // Compute public polynomial coefficients
            var F = f.Commit(g.Point().Base());
            SecretCommits = F.Commits.ToList();

            SessionId = CreateSessionId();

            Aggregator = new Aggregator(g, Pub, Verifiers, SecretCommits, T, SessionId);
            // C = F + G
            Deals = new List<Deal>(Verifiers.Count);
            for (int i = 0; i < Verifiers.Count; i++)
            {
                var fi = f.Eval(i);
                Deals[i] = new Deal
                {
                    SessionId = SessionId,
                    SecShare = fi,
                    Commitments = SecretCommits,
                    T = (uint)T
                };
            }
            HkdfContext = CreateContextID();
            SecretPoly = f;
        }

        // PlaintextDeal returns the plaintext version of the deal destined for peer i.
        // Use this only for testing.
        public Deal PlaintextDeal(int i)
        {
            if (i >= Deals.Count || i < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(i));
            }
            return Deals[i];
        }

        // EncryptedDeal returns the encryption of the deal that must be given to the
        // verifier at index i.
/*        public EncryptedDeal EncryptedDeal(int i)
        {
            var vPub = FindPub(i);
            // gen ephemeral key
            var dhSecret = g.Scalar().Pick(g.RndStream());
            var dhPublic = g.Point().Base().Mul(dhSecret);
            // signs the public key
            MemoryStream strm = new();
            dhPublic.MarshalBinary(strm);
            var dhPublicBuff = strm.ToArray();
            var signature = Schnorr.Sign(g, LongTermKey, dhPublicBuff) ?? throw new Exception("EncryptedDeal: error signing the public key");

            // AES128-GCM
            var pre = DhExchange(g, dhSecret, vPub);
            var gcm = NewAEAD(hash, pre, HkdfContext) ?? throw new Exception("EncryptedDeal: error creating new AEAD");
            var nonce = new byte[gcm.NonceSize()];

            var dealBuff = Protobuf.Encode(Deals[i]) ?? throw new Exception("EncryptedDeal: error encoding the deal");
            var encrypted = gcm.Seal(null, nonce, dealBuff, HkdfContext);
            // var dhBytes = dhPublic.MarshalBinary();
            return (new EncryptedDeal
            {
                DHKey = dhPublicBuff,
                Signature = signature,
                Nonce = nonce,
                Cipher = encrypted
            }, null);
        }
*/
        // EncryptedDeals calls `EncryptedDeal` for each index of the verifier and
        // returns the list of encrypted deals. Each index in the returned list
        // corresponds to the index in the list of verifiers.
 /*       public List<EncryptedDeal> EncryptedDeals()
        {
            var deals = new List<EncryptedDeal>(Verifiers.Count);
            for (int i = 0; i < Verifiers.Count; i++)
            {
                deals.Add(EncryptedDeal(i));
            }
            return deals;
        }
 */
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
        // MinimumT returns a safe value of T that balances secrecy and robustness.
        // It expects n, the total number of participants.
        // T should be adjusted to your threat model. Setting a lower T decreases the
        // difficulty for an adversary to break secrecy. However, a too large T makes
        // it possible for an adversary to prevent recovery (robustness).
        public static int MinimumT(int n)
        {
            return (n + 1) / 2;
        }

        public static bool ValidT(int t, List<IPoint> verifiers)
        {
            return t >= 2 && t <= verifiers.Count && t == (uint)t;
        }

        public byte[] CreateSessionId()
        {
            MemoryStream strm = new();
            Pub.MarshalBinary(strm);
            foreach (var vrf in Verifiers)
            {
                vrf.MarshalBinary(strm);
            }

            foreach (var cmt in SecretCommits)
            {
                cmt.MarshalBinary(strm);
            }
            strm.Write(BitConverter.GetBytes((uint)T));
            return hash.ComputeHash(strm.ToArray());
        }

        // ContextId returns the context slice to be used when encrypting a share

        public byte[] CreateContextID()
        {
            MemoryStream strm = new();
            strm.Write(Encoding.UTF8.GetBytes("vss-dealer"));
            Pub.MarshalBinary(strm);
            strm.Write(Encoding.UTF8.GetBytes("vss-verifiers"));
            foreach (var vrf in Verifiers)
            {
                vrf.MarshalBinary(strm);
            }
            return hash.ComputeHash(strm.ToArray());
        }

            // dhExchange computes the shared key from a private key and a public key
            public static IPoint DhExchange(IScalar ownPrivate, IPoint remotePublic)
            {
                return remotePublic.Mul(ownPrivate);
            }

            private const int sharedKeyLength = 32;

            // newAEAD returns the AEAD cipher to be use to encrypt a share
/*            public AesGcm NewAEAD(Func<HashAlgorithm> fn, IPoint preSharedKey, byte[] context)
            {
                MemoryStream strm = new();
                preSharedKey.MarshalBinary(strm);

                var reader = new Hkdf(fn(), strm.ToArray(), null, context);

                var sharedKey = new byte[sharedKeyLength];
                if (reader.Read(sharedKey, 0, sharedKeyLength) != sharedKeyLength)
                {
                    throw new Exception("Error reading from HKDF");
                }
                var aes = Aes.Create();
                aes.Key = sharedKey;
                return new AesGcm(aes.Key);
            }
*/        }



    // Deal encapsulates the verifiable secret share and is sent by the dealer to a verifier.
    public class Deal
    {
        // Unique session identifier for this protocol run
        public byte[] SessionId { get; set; }

        // Private share generated by the dealer
        public PriShare SecShare { get; set; }

        // Threshold used for this secret sharing run
        public uint T { get; set; }

        // Commitments are the coefficients used to verify the shares against
        public List<IPoint> Commitments { get; set; }
    }

    // EncryptedDeal contains the deal in a encrypted form only decipherable by the
    // correct recipient. The encryption is performed in a similar manner as what is
    // done in TLS. The dealer generates a temporary key pair, signs it with its
    // longterm secret key.
    public class EncryptedDeal
    {
        // Ephemeral Diffie Hellman key
        public byte[] DHKey { get; set; }

        // Signature of the DH key by the longterm key of the dealer
        public byte[] Signature { get; set; }

        // Nonce used for the encryption
        public byte[] Nonce { get; set; }

        // AEAD encryption of the deal marshalled by protobuf
        public byte[] Cipher { get; set; }
    }

    // Response is sent by the verifiers to all participants and holds each
    // individual validation or refusal of a Deal.
    public class Response
    {
        // SessionId related to this run of the protocol
        public byte[] SessionId { get; set; }

        // Index of the verifier issuing this Response from the new set of nodes
        public uint Index { get; set; }

        // false = NO APPROVAL == Complaint , true = APPROVAL
        public Status Status { get; set; }

        // Signature over the whole packet
        public byte[] Signature { get; set; }
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

    // Aggregator is used to collect all deals, and responses for one protocol run.
    // It brings common functionalities for both Dealer and Verifier structs.
    public class Aggregator: Verifiable
    {
        private readonly IGroup g;
        public IPoint Dealer { get; set; }
        public List<IPoint> Commits { get; set; }
        public Dictionary<uint, Response> Responses { get; set; }
        public byte[] Sid { get; set; }
        public Deal Deal { get; set; }
        public int T { get; set; }
        public bool BadDealer { get; set; }
        public bool Timeout { get; set; }
        public Aggregator(IGroup group, IPoint dealer, List<IPoint> verifiers, List<IPoint> commitments, int t, byte[] sid):
            base(verifiers)
        {
            g = group;
            Dealer = dealer;
            Commits = commitments;
            T = t;
            Sid = sid;
            Responses = new Dictionary<uint, Response>();
        }

        // New Empty Aggregator returns a structure capable of storing Responses about a
        // deal and check if the deal is certified or not.
        public Aggregator(IGroup group, List<IPoint> verifiers):
            base(verifiers)
        {
            g = group;
            Responses = new Dictionary<uint, Response>();
        }

/*        public string VerifyResponse(Response r)
        {
            if (Sid != null && !Sid.SequenceEqual(r.SessionId))
            {
                return "vss: receiving inconsistent sessionId in response";
            }

            var pub = FindPub(r.Index);

            var error = Schnorr.Verify(g, pub, r.Hash(g), r.Signature);
            if (error != null)
            {
                return error;
            }

            return AddResponse(r);
        }
*/
    }
}
