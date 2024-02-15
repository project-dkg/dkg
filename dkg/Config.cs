namespace dkg
{
    public class Config
    {
        public IGroup G { get; set; }

        // Longterm is the LongTermKey secret key.
        public IScalar LongTermKey { get; set; }

        // Current group of share holders. It will be null for new DKG.
        public List<IPoint> OldNodes { get; set; }

        // PublicCoeffs are the coefficients of the distributed polynomial needed
        // during the resharing protocol.
        public List<IPoint> PublicCoeffs { get; set; }

        // Expected new group of share holders.
        public List<IPoint> NewNodes { get; set; }

        // Share to refresh.
        //public DistKeyShare Share { get; set; }

        // The threshold to use in order to reconstruct the secret with the produced
        // shares.
        public int Threshold { get; set; }

        // OldThreshold holds the threshold value that was used in the previous
        // configuration.
        public int OldThreshold { get; set; }

        // Reader is an optional field that can hold a user-specified entropy source.
        public System.IO.Stream Reader { get; set; }

        // When UserReaderOnly it set to true, only the user-specified entropy source
        // Reader will be used.
        public bool UserReaderOnly { get; set; }
    }
}
