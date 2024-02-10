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

    // Dealer encapsulates for creating and distributing the shares and for
     // replying to any Responses.
    public class Dealer
    {
        private readonly IGroup g;
        private readonly XOFHelper h;
        public Stream Reader { get; set; }
        public IScalar Long { get; set; }
        public IPoint Pub { get; set; }
        public IScalar Secret { get; set; }
        public List<IPoint> SecretCommits { get; set; }
        public PriPoly SecretPoly { get; set; }
        public List<IPoint> Verifiers { get; set; }
        public byte[] HkdfContext { get; set; }
        public int T { get; set; }
        public byte[] SessionID { get; set; }
        public List<Deal> Deals { get; set; }
        public Aggregator Aggregator { get; set; }

        // NewDealer returns a Dealer capable of leading the secret sharing scheme. It
        // does not have to be trusted by other Verifiers. The security parameter t is
        // the number of shares required to reconstruct the secret. MinimumT() provides
        // a middle ground between robustness and secrecy. Increasing t will increase
        // the secrecy at the cost of the decreased robustness and vice versa. It 
        // returns an error if the t is inferior or equal to 2.
        public Dealer(IGroup group, IScalar longterm, IScalar secret, List<IPoint> verifiers, int t)
        {
            if (!ValidT(t, verifiers))
            {
                throw new ArgumentException($"Dealer: t {t} invalid");
            }

            g = group;
            h = new XOFHelper();

            Long = longterm;
            Secret = secret;
            Verifiers = verifiers;
            T = t;

            var f = new PriPoly(g, T, Secret, new RandomStream());
            Pub = g.Point().Base().Mul(Long);

            // Compute public polynomial coefficients
            var F = f.Commit(g.Point().Base());
            SecretCommits = F.Commits.ToList();

            SessionID = CreateSessionID();

            Aggregator = new Aggregator(g, Pub, Verifiers, SecretCommits, T, SessionID);
            // C = F + G
            Deals = new List<Deal>(Verifiers.Count);
            for (int i = 0; i < Verifiers.Count; i++)
            {
                var fi = f.Eval(i);
                Deals[i] = new Deal
                {
                    SessionID = SessionID,
                    SecShare = fi,
                    Commitments = SecretCommits,
                    T = (uint)T
                };
            }
            HkdfContext = CreateContextID();
            SecretPoly = f;
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

        public static bool ValidT(int t, List<IPoint> verifiers)
        {
            return t >= 2 && t <= verifiers.Count && t == (uint)t;
        }

        public byte[] CreateSessionID()
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
            return h.XOF(strm.ToArray());
        }

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
            return h.XOF(strm.ToArray());
        }
    }

    // Deal encapsulates the verifiable secret share and is sent by the dealer to a verifier.
    public class Deal
    {
        // Unique session identifier for this protocol run
        public byte[] SessionID { get; set; }

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
        // SessionID related to this run of the protocol
        public byte[] SessionID { get; set; }

        // Index of the verifier issuing this Response from the new set of nodes
        public uint Index { get; set; }

        // false = NO APPROVAL == Complaint , true = APPROVAL
        public Status Status { get; set; }

        // Signature over the whole packet
        public byte[] Signature { get; set; }
    }

    public class Justification
    {
        // SessionID related to the current run of the protocol
        public byte[] SessionID { get; set; }

        // Index of the verifier who issued the Complaint,i.e. index of this Deal
        public uint Index { get; set; }

        // Deal in cleartext
        public Deal Deal { get; set; }

        // Signature over the whole packet
        public byte[] Signature { get; set; }
    }

    // Aggregator is used to collect all deals, and responses for one protocol run.
    // It brings common functionalities for both Dealer and Verifier structs.
    public class Aggregator
    {
        private readonly IGroup g;
        public IPoint Dealer { get; set; }
        public List<IPoint> Verifiers { get; set; }
        public List<IPoint> Commits { get; set; }
        public Dictionary<uint, Response> Responses { get; set; }
        public byte[] Sid { get; set; }
        public Deal Deal { get; set; }
        public int T { get; set; }
        public bool BadDealer { get; set; }
        public bool Timeout { get; set; }
        public Aggregator(IGroup group, IPoint dealer, List<IPoint> verifiers, List<IPoint> commitments, int t, byte[] sid)
        {
            g = group;
            Dealer = dealer;
            Verifiers = verifiers;
            Commits = commitments;
            T = t;
            Sid = sid;
            Responses = new Dictionary<uint, Response>();
        }

        // New Empty Aggregator returns a structure capable of storing Responses about a
        // deal and check if the deal is certified or not.
        public Aggregator(IGroup group, List<IPoint> verifiers)
        {
            g = group;
            Verifiers = verifiers;
            Responses = new Dictionary<uint, Response>();
        }

    }
}
