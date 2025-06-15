// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using Kdf108.Domain.Kdf;

#endregion

namespace Kdf108.Domain.Interfaces.Kdf;

public interface IKdfEngine
{
    byte[] Derive(
        KdfMode mode,
        byte[] kdk,
        string label,
        byte[] context,
        long outputLengthInBits,
        KdfOptions options);
}
