using dkg.group;
using dkg.poly;
using dkg.vss;
using Org.BouncyCastle.Pqc.Crypto.Lms;
using System;

namespace dkg
{
    public class DistKeyGenerator
    {
        // config driving the behavior of DistKeyGenerator
        public Config C { get; set; }

        // long-term private key
        public IScalar LongTermKey { get; set; }
        // long-term public key
        public IPoint Pub { get; set; }
        // distributed public key
        public PubPoly Dpub { get; set; }
        // dealer used to distribute shares
        public Dealer Dealer { get; set; }
        // verifiers indexed by dealer index
        public Dictionary<int, Verifier> Verifiers { get; set; }
        // performs the part of the response verification for old nodes
        public Dictionary<int, Aggregator> OldAggregators { get; set; }
        // index in the old list of nodes
        public int Oidx { get; set; }
        // index in the new list of nodes
        public int Nidx { get; set; }
        // old threshold used in the previous DKG
        public int OldT { get; set; }
        // new threshold to use in this round
        public int NewT { get; set; }
        // indicates whether we are in the re-sharing protocol or basic DKG
        public bool IsResharing { get; set; }
        // indicates whether we are able to issue shares or not
        public bool CanIssue { get; set; }
        // Indicates whether we are able to receive a new share or not
        public bool CanReceive { get; set; }
        // indicates whether the node holding the pub key is present in the new list
        public bool NewPresent { get; set; }
        // indicates whether the node is present in the old list
        public bool OldPresent { get; set; }
        // already processed our own deal
        public bool Processed { get; set; }
        // did the timeout / period / already occured or not
        public bool Timeout { get; set; }

        // Takes a Config and returns a DistKeyGenerator that is able
        // to drive the DKG or resharing protocol.
        public DistKeyGenerator(Config c)
        {
            // Check if both new and old nodes list are empty
            if (c.NewNodes.Length == 0 &&  c.OldNodes.Length == 0)
            {
                throw new DkgError("Can't run with empty node list", GetType().Name);
            }

            bool isResharing = false;
            // Check if resharing is required
            if (c.Share != null || c.PublicCoeffs.Length != 0)
            {
                isResharing = true;
            }
            if (isResharing)
            {
                // Check if old nodes list is empty in resharing case
                if (c.OldNodes.Length == 0)
                {
                    throw new DkgError("Resharing config needs old nodes list", GetType().Name);
                }
                // Check if old threshold is zero in resharing case
                if (c.OldThreshold == 0)
                {
                    throw new DkgError("Resharing case needs old threshold field", GetType().Name);
                }
            }

            // canReceive is true by default since in the default DKG mode everyone participates
            bool canReceive = true;
            IPoint pub = Suite.G.Point().Base().Mul(c.LongTermKey);

            int oidx, nidx;
            // findPub method is not defined in your provided code. You need to ensure this method is defined in your project.
            oidx = VssTools.FindPubIdx(c.OldNodes, pub);
            nidx = VssTools.FindPubIdx(c.NewNodes, pub);
            bool oldPresent = oidx != -1,
                 newPresent = nidx != -1;
            // Check if public key is not found in both old and new list
            if (!oldPresent && !newPresent)
            {
                throw new DkgError("Public key not found in old list or new list", GetType().Name);
            }

            // Set new threshold
            int newThreshold = c.Threshold != 0 ? c.Threshold : VssTools.MinimumT(c.NewNodes.Length);

            Dealer? dealer = null;
            bool canIssue = false;
            // Check if resharing is required
            if (c.Share != null)
            {
                // resharing case
                IScalar secretCoeff = c.Share.Share.V;
                dealer = new Dealer(c.LongTermKey, secretCoeff, c.NewNodes, newThreshold);
                canIssue = true;
            }
            else if (!isResharing && newPresent)
            {
                // fresh DKG case
                IScalar secretCoeff = Suite.G.Scalar();
                dealer = new Dealer(c.LongTermKey, secretCoeff, c.NewNodes, newThreshold);
                canIssue = true;
                c.OldNodes = c.NewNodes;
                oidx = VssTools.FindPubIdx(c.OldNodes, pub);
                oldPresent = oidx != -1;
            }

            PubPoly? dpub = null;
            int oldThreshold = 0;
            // Check if we are not in the new list of nodes
            if (!newPresent)
            {
                // if we are not in the new list of nodes, then we definitely can't receive anything
                canReceive = false;
            }
            else if (isResharing && newPresent)
            {
                // Check if we can't receive new shares without the public polynomial
                if (c.PublicCoeffs.Length == 0 && c.Share == null)
                {
                    throw new DkgError("Can't receive new shares without the public polynomial", GetType().Name);
                }
                else if (c.PublicCoeffs.Length != 0)
                {
                    dpub = new PubPoly(Suite.G, Suite.G.Point().Base(), c.PublicCoeffs);

                }
                else if (c.Share != null)
                {
                    // take the commits of the share, no need to duplicate information
                    c.PublicCoeffs = c.Share.Commits;
                    dpub = new PubPoly(Suite.G, Suite.G.Point().Base(), c.PublicCoeffs);
                }
                // oldThreshold is only useful in the context of a new share holder, to make sure there are enough correct deals from the old nodes.
                canReceive = true;
                oldThreshold = c.PublicCoeffs!.Length;
            }

            // Initialize properties
            C = c;
            LongTermKey = c.LongTermKey;
            Pub = pub;
            Dpub = dpub!;
            Dealer = dealer!;
            Verifiers = [];
            OldAggregators = [];
            Oidx = oldPresent ? oidx : 0;
            Nidx = newPresent ? nidx : 0;
            OldT = oldThreshold;
            NewT = newThreshold;
            IsResharing = isResharing;
            CanIssue = canIssue;
            CanReceive = canReceive;
            NewPresent = newPresent;
            OldPresent = oldPresent;
            Processed = false;
            Timeout = false;

            // Initialize verifiers if newPresent is true
            if (newPresent)
            {
                // initVerifiers method is not defined in your provided code. You need to ensure this method is defined in your project.
                InitVerifiers();
            }
        }

        // CreateDistKeyGenerator returns a dist key generator ready to create a fresh
        // distributed key with the regular DKG protocol.
        public static DistKeyGenerator CreateDistKeyGenerator(IScalar longterm, IPoint[] participants, int t)
        {
            var c = new Config()
            {
                LongTermKey = longterm, 
                NewNodes = participants,
                Threshold = t
            };
            return new DistKeyGenerator(c);
        }

        private void InitVerifiers()
        {
            Dictionary<string, bool> alreadyTaken = [];
            IPoint[] verifierList = C.NewNodes;
            IPoint[] dealerList = C.OldNodes;
            Dictionary<int, Verifier> verifiers = [];
            for (int i = 0; i < dealerList.Length; i++)
            {
                IPoint pub = dealerList[i];
                if (alreadyTaken.ContainsKey(pub.ToString()!))
                {
                    throw new DkgError("Duplicate public key in NewNodes list", GetType().Name);
                }
                alreadyTaken[pub.ToString()!] = true;
                Verifier ver = new(C.LongTermKey, pub, verifierList);
                // set that the number of approval for this deal must be at the given threshold regarding the new nodes. (see config)
                ver.SetThreshold(C.Threshold);
                verifiers[i] = ver;
            }
            Verifiers = verifiers;
        }

        // Deals returns all the deals that must be broadcasted to all participants in
        // the new list. The deal corresponding to this DKG is already added to this DKG
        // and is ommitted from the returned map. To know which participant a deal
        // belongs to, loop over the keys as indices in the list of new participants:
        //
        //	for i,dd := range distDeals {
        //	   sendTo(participants[i],dd)
        //	}
        //
        // If this method cannot process its own Deal, that indicates a
        // severe problem with the configuration or implementation and
        // results in a panic.
        public Dictionary<int, DistDeal> Deals()
        {
            Dictionary<int, DistDeal> dd = [];
            if (CanIssue)
            {
                // Otherwise we do not hold a share, so we cannot make a deal, so
                // return an empty dictionary and no exception. This makes callers not
                // need to care if they are in a resharing context or not.

                EncryptedDeal[] deals;
                try
                {
                    deals = Dealer.EncryptedDeals();
                }
                catch (Exception e)
                {
                    throw new DkgError($"Error generating encrypted deals: {e.Message}", GetType().Name);
                }

                for (int i = 0; i < C.NewNodes.Length; i++)
                {
                    DistDeal distd = new(Oidx, deals[i]);

                    // sign the deal
                    byte[] buff;
                    try
                    {
                        buff = distd.GetBytes();
                        distd.Signature = Schnorr.Sign(Suite.G, Suite.Hash, LongTermKey, buff);
                    }
                    catch (Exception e)
                    {
                        throw new DkgError($"Error signing the deal: {e.Message}", GetType().Name);
                    }

                    // if there is a resharing in progress, nodes that stay must send their
                    // deals to the old nodes, otherwise old nodes won't get responses from
                    // staying nodes and won't be certified.
                    if (i == Nidx && NewPresent && !IsResharing)
                    {
                        if (Processed)
                        {
                            continue;
                        }
                        Processed = true;
                        DistResponse resp = ProcessDeal(distd);
                        if (resp.VssResponse.Status != ResponseStatus.Approval)
                        {
                            throw new DkgError($"Own deal gave a complaint", GetType().Name);
                        }
                        continue;
                    }
                    dd[i] = distd;
                }
            }
            return dd;
        }

        // ProcessDeal takes a Deal created by Deals() and stores and verifies it. It
        // returns a Response to broadcast to every other participant, including the old
        // participants. It returns an error in case the deal has already been stored,
        // or if the deal is incorrect (see vss.Verifier.ProcessEncryptedDeal).
        public DistResponse ProcessDeal(DistDeal dd)
        {
            if (!NewPresent)
                throw new DkgError("dkg: unexpected deal for unlisted dealer in a new list", GetType().Name);

            IPoint? pub = (IsResharing ? VssTools.GetPub(C.OldNodes, dd.Index) :
                                         VssTools.GetPub(C.NewNodes, dd.Index)) ?? 
                                         throw new DkgError("dkg: dist deal out of bounds index", GetType().Name);

            // verify signature
            byte[] buff;
            try
            {
                buff = dd.GetBytes();
                Schnorr.Verify(Suite.G, Suite.Hash, pub, buff, dd.Signature);//!!!
            }
            catch (Exception e)
            {
                throw new DkgError($"Error verifying the deal: {e.Message}", GetType().Name);
            }

            Verifiers.TryGetValue(dd.Index, out Verifier? ver);
            if (ver == null)
                throw new DkgError("missing verifiers", GetType().Name);

            Response? resp;
            try
            {
                resp = ver.ProcessEncryptedDeal(dd.VssDeal);
            }
            catch (Exception e)
            {
                throw new DkgError($"Error processing encrypted deal: {e.Message}", GetType().Name);
            }

            Func<DistResponse> reject = () =>
            {
                int idx = VssTools.FindPubIdx(C.NewNodes, pub);
                if (idx != -1)
                {
                    // the dealer is present in both list, so we set its own response
                    // (as a verifier) to a complaint since he won't do it himself
                    Verifiers[dd.Index].SetResponseDkg(idx, ResponseStatus.Complaint);
                }
                // indicate to VSS that this dkg's new status is complaint for this
                // deal
                Verifiers[dd.Index].SetResponseDkg(Nidx, ResponseStatus.Complaint);
                resp.Status = ResponseStatus.Complaint;
                byte[] s;
                try
                {
                    s = Schnorr.Sign(Suite.G, Suite.Hash, LongTermKey, resp.Hash());
                }
                catch (Exception e)
                {
                    throw new DkgError($"Error signing the response: {e.Message}", GetType().Name);
                }
                resp.Signature = s;
                return new DistResponse(dd.Index, resp);
            };

            if (IsResharing && CanReceive)
            {
                // verify share integrity wrt to the dist. secret
                IPoint[] dealCommits = ver.Aggregator.Commitments;
                // Check that the received committed share is equal to the one we
                // generate from the known public polynomial
                PubShare expectedPubShare = Dpub.Eval(dd.Index);
                if (!expectedPubShare.V.Equals(dealCommits[0]))
                {
                    return reject();
                }
            }

            // If the dealer in the old list is also present in the new list, then set
            // his response to approval since he won't issue his own response for his
            // own deal.
            // In the case of resharing the dealer will issue his own response in order
            // for the old comities to get responses and be certified, which is why we
            // don't add it manually there.
            int newIdx = VssTools.FindPubIdx(C.NewNodes, pub);
            if (newIdx != -1 && !IsResharing)
                Verifiers[dd.Index].SetResponseDkg(newIdx, ResponseStatus.Approval);

            return new DistResponse(dd.Index, resp);
        }

        // ProcessResponse takes a response from every other peer.  If the response
        // designates the deal of another participant than this dkg, this dkg stores it
        // and returns nil with a possible error regarding the validity of the response.
        // If the response designates a deal this dkg has issued, then the dkg will process
        // the response, and returns a justification.
        public DistJustification? ProcessResponse(DistResponse resp)
        {
            if (IsResharing && CanIssue && !NewPresent)
                 return ProcessResharingResponse(resp);

            Verifiers.TryGetValue(resp.Index, out Verifier? v);
            if (v == null)
                throw new DkgError($"Responses received for unknown dealer {resp.Index}", GetType().Name);

            string? vssError;
            try
            {
                vssError = v.ProcessResponse(resp.VssResponse);
            }
            catch (Exception ex)
            {
                throw new DkgError($"Error processing the response: {ex.Message}", GetType().Name);
            }

            if (vssError != null)
                throw new DkgError(vssError, GetType().Name);

            int myIdx = Oidx;
            if (!CanIssue || resp.Index != myIdx)
                // no justification if we dont issue deals or the deal's not from us
                return null;

            Justification? j;
            try
            {
                j = Dealer.ProcessResponse(resp.VssResponse);
            }
            catch (Exception ex)
            {
                throw new DkgError($"Error processing the response in the dealer: {ex.Message}", GetType().Name);
            }

            if (j == null)
                return null;

            try
            {
                v.ProcessJustification(j);
            }
            catch (Exception ex)
            {
                throw new DkgError($"Error processing the justification: {ex.Message}", GetType().Name);
            }

            return new DistJustification(Oidx, j);
        }
        // special case when an node that is present in the old list but not in the
        // new,i.e. leaving the group. This node does not have any verifiers since it
        // can't receive shares. This function makes some check on the response and
        // returns a justification if the response is invalid.
        public DistJustification? ProcessResharingResponse(DistResponse resp)
        {
            OldAggregators.TryGetValue(resp.Index, out Aggregator? agg);
            if (agg == null)
            {
                agg = new Aggregator(C.NewNodes);
                OldAggregators[resp.Index] = agg;
            }

            try
            {
                agg.ProcessResponse(resp.VssResponse);
            }
            catch (Exception ex)
            {
                throw new DkgError($"Error processing the response in the aggregator: {ex.Message}", GetType().Name);
            }

            if (resp.Index != Oidx)
                return null;

            if (resp.VssResponse.Status == ResponseStatus.Approval)
                return null;

            // status is complaint and it is about our deal
            Deal deal;
            try
            {
                deal = Dealer.PlaintextDeal(resp.VssResponse.Index);
            }
            catch (Exception ex)
            {
                throw new DkgError($"Resharing response can't get deal: {ex.Message}", GetType().Name);
            }

            return new DistJustification(
                Oidx,
                new Justification(
                    Dealer.SessionId,
                    resp.VssResponse.Index, // good index because of signature check
                    deal));

        }
        // ProcessJustification takes a justification and validates it. It returns an
        // error in case the justification is wrong.
        public void ProcessJustification(DistJustification j)
        {
            Verifiers.TryGetValue(j.Index, out Verifier? v);
            if (v == null)
                throw new DkgError("Justification received but there is no deal for it.", GetType().Name);

            try
            {
                v.ProcessJustification(j.VssJustification);
            }
            catch (Exception ex)
            {
                throw new DkgError($"Error processing the justification: {ex.Message}", GetType().Name);
            }
        }

        // SetTimeout triggers the timeout on all verifiers, and thus makes sure
        // all verifiers have either responded, or have a StatusComplaint response.
        public void SetTimeout()
        {
            Timeout = true;
            foreach (var v in Verifiers.Values)
            {
                v.SetTimeout();
            }
        }

        // ThresholdCertified returns true if a THRESHOLD of deals are certified. To know the
        // list of correct receiver, one can call d.QUAL()
        // NOTE:
        // This method should only be used after a certain timeout - mimicking the
        // synchronous assumption of the Pedersen's protocol. One can call
        // `Certified()` to check if the DKG is finished and stops it pre-emptively
        // if all deals are correct.  If called *before* the timeout, there may be
        // inconsistencies in the shares produced. For example, node 1 could have
        // aggregated shares from 1, 2, 3 and node 2 could have aggregated shares from
        // 2, 3 and 4.
        public bool ThresholdCertified()
        {
            if (IsResharing)
            {
                // in resharing case, we have two threshold. Here we want the number of
                // deals to be at least what the old threshold was. (and for each deal,
                // we want the number of approval to be a least what the new threshold
                // is).
                return QUAL().Count >= C.OldThreshold;
            }
            // in dkg case, the threshold is symmetric -> # verifiers = # dealers
            return QUAL().Count >= C.Threshold;
        }

        // QualifiedShares returns the set of shares holder index that are considered
        // valid. In particular, it computes the list of common share holders that
        // replied with an approval (or with a complaint later on justified) for each
        // deal received. These indexes represent the new share holders with valid (or
        // justified) shares from certified deals.  Detailled explanation:
        // To compute this list, we consider the scenario where a share holder replied
        // to one share but not the other, as invalid, as the library is not currently
        // equipped to deal with that scenario.
        // 1.  If there is a valid complaint non-justified for a deal, the deal is deemed
        // invalid
        // 2. if there are no response from a share holder, the share holder is
        // removed from the list.
        public List<int> QualifiedShares()
        {
            var invalidSh = new Dictionary<int, bool>();
            var invalidDeals = new Dictionary<int, bool>();
            // compute list of invalid deals according to 1.
            foreach (var dealerIndex in Verifiers.Keys)
            {
                var verifier = Verifiers[dealerIndex];
                var responses = verifier.Responses();
                if (responses.Count == 0)
                {
                    // don't analyzes "empty" deals - i.e. dealers that never sent
                    // their deal in the first place.
                    invalidDeals[dealerIndex] = true;
                }
                for (int holderIndex = 0; holderIndex < C.NewNodes.Length; holderIndex++)
                {
                    if (responses.TryGetValue(holderIndex, out var resp) && resp.Status == ResponseStatus.Complaint)
                    {
                        // 1. rule
                        invalidDeals[dealerIndex] = true;
                        break;
                    }
                }
            }

            // compute list of invalid share holders for valid deals
            foreach (var dealerIndex in Verifiers.Keys)
            {
                // skip analyze of invalid deals
                if (invalidDeals.ContainsKey(dealerIndex))
                {
                    continue;
                }
                var verifier = Verifiers[dealerIndex];
                var responses = verifier.Responses();
                for (int holderIndex = 0; holderIndex < C.NewNodes.Length; holderIndex++)
                {
                    if (!responses.ContainsKey(holderIndex))
                    {
                        // 2. rule - absent response
                        invalidSh[holderIndex] = true;
                    }
                }
            }

            var validHolders = new List<int>();
            for (int holderIndex = 0; holderIndex < C.NewNodes.Length; holderIndex++)
            {
                if (!invalidSh.ContainsKey(holderIndex))
                {
                    validHolders.Add(holderIndex);
                }
            }
            return validHolders;
        }

        // ExpectedDeals returns the number of deals that this node will
        // receive from the other participants.
        public int ExpectedDeals()
        {
            if (NewPresent && OldPresent)
            {
                return C.OldNodes.Length - 1;
            }
            else if (NewPresent && !OldPresent)
            {
                return C.OldNodes.Length;
            }
            else
            {
                return 0;
            }
        }

        // QUAL returns the index in the list of participants that forms the QUALIFIED
        // set, i.e. the list of Certified deals.
        // It does NOT take into account any malicious share holder which share may have
        // been revealed, due to invalid complaint.
        public List<int> QUAL()
        {
            var good = new List<int>();
            if (IsResharing && CanIssue && !NewPresent)
            {
                OldQualIter((i, v) =>
                {
                    good.Add(i);
                    return true;
                });
            }
            else
            {
                QualIter((i, v) =>
                {
                    good.Add(i);
                    return true;
                });
            }
            return good;
        }

        public bool IsInQUAL(int idx)
        {
            bool found = false;
            QualIter((i, v) =>
            {
                if (i == idx)
                {
                    found = true;
                    return false;
                }
                return true;
            });
            return found;
        }

        public void QualIter(Func<int, Verifier, bool> fn)
        {
            foreach (var i in Verifiers.Keys)
            {
                var v = Verifiers[i];
                if (v.DealCertified())
                {
                    if (!fn(i, v))
                    {
                        break;
                    }
                }
            }
        }

        public void OldQualIter(Func<int, Aggregator, bool> fn)
        {
            foreach (var i in OldAggregators.Keys)
            {
                var v = OldAggregators[i];
                if (v.DealCertified())
                {
                    if (!fn(i, v))
                    {
                        break;
                    }
                }
            }
        }

        // DistKeyShare generates the distributed key relative to this receiver.
        // It throws an error if something is wrong such as not enough deals received.
        // The shared secret can be computed when all deals have been sent and
        // basically consists of a public point and a share. The public point is the sum
        // of all aggregated individual public commits of each individual secrets.
        // The share is evaluated from the global Private Polynomial, basically SUM of
        // fj(i) for a receiver i.
        public DistKeyShare DistKeyShare()
        {
            if (!ThresholdCertified())
            {
                throw new DkgError("Distributed key not certified", GetType().Name);
            }
            if (!CanReceive)
            {
                throw new DkgError("Should not expect to compute any dist. share", GetType().Name);
            }

                return IsResharing ? ResharingKey() : DkgKey();
        }

        public DistKeyShare DkgKey()
        {
            var sh = Suite.G.Scalar().Zero();
            PubPoly? pub = null;
            Exception? err = null;
            QualIter((i, v) =>
            {
                // share of dist. secret = sum of all share received.
                var deal = v.Deal();
                var s = deal.SecShare.V;
                sh = sh.Add(s);
                // Dist. public key = sum of all revealed commitments
                var poly = new PubPoly(Suite.G, Suite.G.Point().Base(), deal.Commitments);
                if (pub == null)
                {
                    // first polynomial we see (instead of generating n empty commits)
                    pub = poly;
                    return true;
                }
                try
                {
                    pub = pub.Add(poly);
                    return true;
                }
                catch (Exception e)
                {
                    err = e;
                    return false;
                }
            });

            if (err != null)
            {
                throw new DkgError($"Error in DkgKey: {err}", GetType().Name);
            }
            var commits = pub.Commits;

            return new DistKeyShare(commits, new PriShare(Nidx, sh), Dealer.SecretPoly.Coeffs);
        }

        public DistKeyShare ResharingKey()
        {
            // only old nodes sends shares
            var shares = new PriShare[C.OldNodes.Length];
            var coeffs = new IPoint[C.OldNodes.Length][];
            QualIter((i, v) =>
            {
                var deal = v.Deal();
                coeffs[i] = deal.Commitments;
                // share of dist. secret. Invertion of rows/column
                deal.SecShare.I = i;
                shares[i] = deal.SecShare;
                return true;
            });

            // the private polynomial is generated from the old nodes, thus inheriting
            // the old threshold condition
            var priPoly = PriPoly.RecoverPriPoly(Suite.G, shares, OldT, C.OldNodes.Length) ??
                          throw new DkgError("Could not recover PriPoly", GetType().Name);
             
            var privateShare = new PriShare(Nidx, priPoly.Secret());

            // recover public polynomial by interpolating coefficient-wise all
            // polynomials
            // the new public polynomial must however have "newT" coefficients since it
            // will be held by the new nodes.
            var finalCoeffs = new IPoint[NewT];
            for (int i = 0; i < NewT; i++)
            {
                var tmpCoeffs = new PubShare[coeffs.Length];
                // take all i-th coefficients
                for (int j = 0; j < coeffs.Length; j++)
                {
                    if (coeffs[j] != null)
                    {
                        tmpCoeffs[j] = new PubShare(j, coeffs[j][i]);
                    }
                }

                // using the old threshold / length because there are at most
                // len(d.c.OldNodes) i-th coefficients since they are the one generating one
                // each, thus using the old threshold.
                var coeff = PubPoly.RecoverCommit(Suite.G, tmpCoeffs, OldT, C.OldNodes.Length);
                finalCoeffs[i] = coeff;
            }

            // Reconstruct the final public polynomial
            var pubPoly = new PubPoly(Suite.G, finalCoeffs);

            if (!pubPoly.Check(privateShare))
            {
                throw new DkgError("Share do not correspond to public polynomial ><", GetType().Name);
            }
            return new DistKeyShare(finalCoeffs, privateShare, priPoly.Coeffs);
        }

        // Certified returns true if *all* deals are certified. This method should
        // be called before the timeout occurs, as to pre-emptively stop the DKG
        // protocol if it is already finished before the timeout.
        public bool Certified()
        {
            var good = new List<int>();
            if (IsResharing && CanIssue && !NewPresent)
            {
                OldQualIter((i, v) =>
                {
                    if (v.MissingResponses().Length > 0)
                    {
                        return false;
                    }
                    good.Add(i);
                    return true;
                });
            }
            else
            {
                QualIter((i, v) =>
                {
                    if (v.MissingResponses().Length > 0)
                    {
                        return false;
                    }
                    good.Add(i);
                    return true;
                });
            }
            return good.Count >= C.OldNodes.Length;
        }
    }
}


