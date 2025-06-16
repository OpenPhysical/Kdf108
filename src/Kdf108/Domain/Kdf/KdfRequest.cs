// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

namespace Kdf108.Domain.Kdf
{
    public sealed class KdfRequest
    {
        public KdfRequest(
            byte[] keyDerivationKey,
            string label,
            byte[] context,
            long outputLengthBits,
            KdfOptions options)
        {
            KeyDerivationKey = keyDerivationKey;
            Label = label;
            Context = context;
            OutputLengthBits = outputLengthBits;
            Options = options;
        }

        public byte[] KeyDerivationKey { get; set; }
        public string Label { get; set; }
        public byte[] Context { get; set; }
        public long OutputLengthBits { get; set; }
        public KdfOptions Options { get; set; }
    }
}
