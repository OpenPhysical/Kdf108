// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System;
using Kdf108.Domain.Interfaces.Prf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace Kdf108.Infrastructure.Prf;

public sealed class HmacPrf : IPrf
{
    private readonly Func<IDigest> _digestFactory;

    public HmacPrf(Func<IDigest> digestFactory) =>
        _digestFactory = digestFactory ?? throw new ArgumentNullException(nameof(digestFactory));

    public int OutputSizeBits => _digestFactory().GetDigestSize() * 8;

    public byte[] Compute(byte[] key, byte[] data) =>
        CreateHmacInstance(key)
            .ApplyData(data)
            .GetResult();

    private HMac CreateHmacInstance(byte[] key)
    {
        IDigest? digest = _digestFactory();
        HMac hmac = new(digest);
        hmac.Init(new KeyParameter(key));
        return hmac;
    }
}
