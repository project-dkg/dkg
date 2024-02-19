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

namespace dkg
{
    // Config holds all required information to run a fresh DKG protocol or a
    // resharing protocol. In the case of a new fresh DKG protocol, one must fill
    // the following fields: Suite, Longterm, NewNodes, Threshold (opt). In the case
    // of a resharing protocol, one must fill the following: Suite, Longterm,
    // OldNodes, NewNodes. If the node using this config is creating new shares
    // (i.e. it belongs to the current group), the Share field must be filled in
    // with the current share of the node. If the node using this config is a new
    // addition and thus has no current share, the PublicCoeffs field be must be
    // filled in.
    public class Config
    {
        // Longterm is the LongTermKey secret key.
        public IScalar? LongTermKey { get; set; }

        // Current group of share holders. It will be null for new DKG.
        public IPoint[] OldNodes { get; set; }

        // PublicCoeffs are the coefficients of the distributed polynomial needed
        // during the resharing protocol.
        public IPoint[] PublicCoeffs { get; set; }

        // Expected new group of share holders.
        public IPoint[] NewNodes { get; set; }

        // Share to refresh.
        public DistKeyShare? Share { get; set; }

        // The threshold to use in order to reconstruct the secret with the produced
        // shares.
        public int Threshold { get; set; }

        // OldThreshold holds the threshold value that was used in the previous
        // configuration.
        public int OldThreshold { get; set; }

        public Config() 
        { 
            LongTermKey = null;
            OldNodes = [];
            PublicCoeffs = [];
            NewNodes = [];
            Share = null; 
            Threshold = 0;
            OldThreshold = 0;
        }

    }
}
