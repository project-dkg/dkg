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

namespace ATestDkg
{
    internal class Node
    {
        public DistKeyGenerator Dkg { get; set; }
        public IPoint PubKey { get; set; }
        public IScalar PrivKey { get; set; }
        public List<DistDeal> Deals { get; set; }
        public List<DistResponse> Resps { get; set; }
        public PriShare SecretShare { get; set; }

    }

    internal class testEndtoEnd
    {
        [Test]
        public void Test_Example_DKG()
        {
            // The number of nodes for this test
            int n = 7;

            // Define a node structure
            var nodes = new Node[n];
            var pubKeys = new IPoint[n];

            // 1. Init the nodes
            for (int i = 0; i < n; i++)
            {
                var privKey = Suite.G.Scalar();
                var pubKey = Suite.G.Base().Mul(privKey);
                pubKeys[i] = pubKey;
                nodes[i] = new Node
                {
                    PubKey = pubKey,
                    PrivKey = privKey,
                    Deals = new List<DistDeal>(),
                    Resps = new List<DistResponse>()
                };
            }

            // 2. Create the DKGs on each node
            for (int i = 0; i < n; i++)
            {
                var dkg = DistKeyGenerator.CreateDistKeyGenerator(nodes[i].PrivKey, pubKeys, n);
                nodes[i].Dkg = dkg;
            }

            // 3. Each node sends its Deals to the other nodes
            foreach (var node in nodes)
            {
                var deals = node.Dkg.Deals();
                foreach (var deal in deals)
                {
                    nodes[deal.Key].Deals.Add(deal.Value);
                }
            }

            // 4. Process the Deals on each node and send the responses to the other nodes
            for (int i = 0; i < n; i++)
            {
                foreach (var deal in nodes[i].Deals)
                {
                    var resp = nodes[i].Dkg.ProcessDeal(deal);
                    for (int j = 0; j < n; j++)
                    {
                        if (j == i) continue;
                        nodes[j].Resps.Add(resp);
                    }
                }
            }

            // 5. Process the responses on each node
            foreach (var node in nodes)
            {
                foreach (var resp in node.Resps)
                {
                    node.Dkg.ProcessResponse(resp);
                }
            }

            // 6. Check and print the qualified shares
            foreach (var node in nodes)
            {
                Assert.Multiple(() =>
                {
                    Assert.That(node.Dkg.Certified(), Is.True);
                    Assert.That(node.Dkg.QualifiedShares().Count, Is.EqualTo(n));
                    Assert.That(node.Dkg.QUAL().Count, Is.EqualTo(n));
                });
            }

            // 7. Get the secret shares and public key
            var shares = new PriShare[n];
            IPoint? publicKey = null;
            for (int i = 0; i < n; i++)
            {
                var distrKey = nodes[i].Dkg.DistKeyShare();
                shares[i] = distrKey.PriShare();
                publicKey = distrKey.Public();
                nodes[i].SecretShare = distrKey.PriShare();
                Console.WriteLine("Distributed public key: " + publicKey);
            }

            // 8. Variant A - Encrypt a secret with the public key and decrypt it with
            // the reconstructed shared secret key. Reconstructing the shared secret key
            // in not something we should do as it gives the power to decrypt any
            // further messages encrypted with the shared public key. For this we show
            // in variant B how to make nodes send back partial decryptions instead of
            // their shares. In variant C the nodes return partial decrpytions that are
            // encrypted under a provided public key.

            string message = "Hello world";

            var cipher = ECElGamalEncryption.Encrypt(Suite.G, publicKey!, message);
            IScalar secretKey = PriPoly.RecoverSecret(Suite.G, shares, n, n);

            var decryptedMessage = ECElGamalEncryption.DecryptString(Suite.G, secretKey, cipher);
            Assert.That(decryptedMessage, Is.EqualTo(message));


            // 8. Variant B - Each node provide only a partial decryption by sending its
            // public share. We then reconstruct the public commitment with those public
            // shares.


            // 8 Variant C - Nodes return a partial decryption under the encryption from
            // the client's provided public key. This is useful in case the decryption
            // happens in public. In that case the decrypted message is never released
            // in clear, but the message is revealed re-encrypted under the provided
            // public key.
            //
            // Here is the crypto that happens in 3 phases:
            //
            // (1) Message encryption:
            //
            // r: random point
            // A: dkg public key
            // G: curve's generator
            // M: message to encrypt
            // (C, U): encrypted message
            //
            // C = rA + M
            // U = rG
            //
            // (2) Node's partial decryption
            //
            // V: node's public re-encrypted share
            // o: node's private share
            // Q: client's public key (pG)
            //
            // V = oU + oQ
            //
            // (3) Message's decryption
            //
            // R: recovered commit (f(V1, V2, ...Vi)) using Lagrange interpolation
            // p: client's private key
            // M': decrypted message
            //
            // M' = C - (R - pA)

            // 9. Re-share the DKG key
            // ... (omitted for brevity)
        }
    }
}
