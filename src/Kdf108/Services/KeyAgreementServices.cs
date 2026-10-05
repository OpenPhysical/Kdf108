// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

// Generated shape: one service method per static scheme method. ApiConventionTests checks they stay identical.

using Kdf108.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kdf108;

/// <summary>SP 800-56A ECC key agreement as an injectable service. Mirrors <see cref="EcSchemes"/>; inject it, or construct <see cref="EcKeyAgreement"/> directly.</summary>
public interface IEcKeyAgreement
{
    /// <inheritdoc cref="EcSchemes.Ephemeral"/>
    byte[] Ephemeral(EcEphemeralKeyPair localEphemeral, EcEphemeralPublicKey remoteEphemeral);
    /// <inheritdoc cref="EcSchemes.Static"/>
    byte[] Static(EcStaticKeyPair localStatic, EcStaticPublicKey remoteStatic);
    /// <inheritdoc cref="EcSchemes.OneFlowAsPartyU"/>
    byte[] OneFlowAsPartyU(EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic);
    /// <inheritdoc cref="EcSchemes.OneFlowAsPartyV"/>
    byte[] OneFlowAsPartyV(EcStaticKeyPair localStatic, EcEphemeralPublicKey remoteEphemeral);
    /// <inheritdoc cref="EcSchemes.Hybrid"/>
    byte[] Hybrid(EcStaticKeyPair localStatic, EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic, EcEphemeralPublicKey remoteEphemeral);
    /// <inheritdoc cref="EcSchemes.HybridOneFlowAsPartyU"/>
    byte[] HybridOneFlowAsPartyU(EcStaticKeyPair localStatic, EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic);
    /// <inheritdoc cref="EcSchemes.HybridOneFlowAsPartyV"/>
    byte[] HybridOneFlowAsPartyV(EcStaticKeyPair localStatic, EcStaticPublicKey remoteStatic, EcEphemeralPublicKey remoteEphemeral);
    /// <inheritdoc cref="EcSchemes.Mqv2"/>
    byte[] Mqv2(EcStaticKeyPair localStatic, EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic, EcEphemeralPublicKey remoteEphemeral);
    /// <inheritdoc cref="EcSchemes.Mqv1AsPartyU"/>
    byte[] Mqv1AsPartyU(EcStaticKeyPair localStatic, EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic);
    /// <inheritdoc cref="EcSchemes.Mqv1AsPartyV"/>
    byte[] Mqv1AsPartyV(EcStaticKeyPair localStatic, EcStaticPublicKey remoteStatic, EcEphemeralPublicKey remoteEphemeral);
}

/// <summary>The logging implementation of <see cref="IEcKeyAgreement"/>. Stateless and thread-safe.</summary>
public sealed class EcKeyAgreement(ILogger<EcKeyAgreement>? logger = null) : IEcKeyAgreement
{
    private readonly ILogger _logger = logger ?? NullLogger<EcKeyAgreement>.Instance;

    /// <inheritdoc/>
    public byte[] Ephemeral(EcEphemeralKeyPair localEphemeral, EcEphemeralPublicKey remoteEphemeral)
    {
        try
        {
            byte[] z = EcSchemes.Ephemeral(localEphemeral, remoteEphemeral);
            Log.Completed(_logger, "SP 800-56A", "ECC Ephemeral", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A ECC Ephemeral", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Static(EcStaticKeyPair localStatic, EcStaticPublicKey remoteStatic)
    {
        try
        {
            byte[] z = EcSchemes.Static(localStatic, remoteStatic);
            Log.Completed(_logger, "SP 800-56A", "ECC Static", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A ECC Static", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] OneFlowAsPartyU(EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic)
    {
        try
        {
            byte[] z = EcSchemes.OneFlowAsPartyU(localEphemeral, remoteStatic);
            Log.Completed(_logger, "SP 800-56A", "ECC OneFlowAsPartyU", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A ECC OneFlowAsPartyU", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] OneFlowAsPartyV(EcStaticKeyPair localStatic, EcEphemeralPublicKey remoteEphemeral)
    {
        try
        {
            byte[] z = EcSchemes.OneFlowAsPartyV(localStatic, remoteEphemeral);
            Log.Completed(_logger, "SP 800-56A", "ECC OneFlowAsPartyV", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A ECC OneFlowAsPartyV", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Hybrid(EcStaticKeyPair localStatic, EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic, EcEphemeralPublicKey remoteEphemeral)
    {
        try
        {
            byte[] z = EcSchemes.Hybrid(localStatic, localEphemeral, remoteStatic, remoteEphemeral);
            Log.Completed(_logger, "SP 800-56A", "ECC Hybrid", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A ECC Hybrid", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] HybridOneFlowAsPartyU(EcStaticKeyPair localStatic, EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic)
    {
        try
        {
            byte[] z = EcSchemes.HybridOneFlowAsPartyU(localStatic, localEphemeral, remoteStatic);
            Log.Completed(_logger, "SP 800-56A", "ECC HybridOneFlowAsPartyU", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A ECC HybridOneFlowAsPartyU", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] HybridOneFlowAsPartyV(EcStaticKeyPair localStatic, EcStaticPublicKey remoteStatic, EcEphemeralPublicKey remoteEphemeral)
    {
        try
        {
            byte[] z = EcSchemes.HybridOneFlowAsPartyV(localStatic, remoteStatic, remoteEphemeral);
            Log.Completed(_logger, "SP 800-56A", "ECC HybridOneFlowAsPartyV", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A ECC HybridOneFlowAsPartyV", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Mqv2(EcStaticKeyPair localStatic, EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic, EcEphemeralPublicKey remoteEphemeral)
    {
        try
        {
            byte[] z = EcSchemes.Mqv2(localStatic, localEphemeral, remoteStatic, remoteEphemeral);
            Log.Completed(_logger, "SP 800-56A", "ECC Mqv2", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A ECC Mqv2", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Mqv1AsPartyU(EcStaticKeyPair localStatic, EcEphemeralKeyPair localEphemeral, EcStaticPublicKey remoteStatic)
    {
        try
        {
            byte[] z = EcSchemes.Mqv1AsPartyU(localStatic, localEphemeral, remoteStatic);
            Log.Completed(_logger, "SP 800-56A", "ECC Mqv1AsPartyU", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A ECC Mqv1AsPartyU", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Mqv1AsPartyV(EcStaticKeyPair localStatic, EcStaticPublicKey remoteStatic, EcEphemeralPublicKey remoteEphemeral)
    {
        try
        {
            byte[] z = EcSchemes.Mqv1AsPartyV(localStatic, remoteStatic, remoteEphemeral);
            Log.Completed(_logger, "SP 800-56A", "ECC Mqv1AsPartyV", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A ECC Mqv1AsPartyV", ex))
        {
            throw;
        }
    }
}

/// <summary>SP 800-56A FFC key agreement as an injectable service. Mirrors <see cref="FfcSchemes"/>; inject it, or construct <see cref="FfcKeyAgreement"/> directly.</summary>
public interface IFfcKeyAgreement
{
    /// <inheritdoc cref="FfcSchemes.Ephemeral"/>
    byte[] Ephemeral(FfcEphemeralKeyPair localEphemeral, FfcEphemeralPublicKey remoteEphemeral);
    /// <inheritdoc cref="FfcSchemes.Static"/>
    byte[] Static(FfcStaticKeyPair localStatic, FfcStaticPublicKey remoteStatic);
    /// <inheritdoc cref="FfcSchemes.OneFlowAsPartyU"/>
    byte[] OneFlowAsPartyU(FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic);
    /// <inheritdoc cref="FfcSchemes.OneFlowAsPartyV"/>
    byte[] OneFlowAsPartyV(FfcStaticKeyPair localStatic, FfcEphemeralPublicKey remoteEphemeral);
    /// <inheritdoc cref="FfcSchemes.Hybrid"/>
    byte[] Hybrid(FfcStaticKeyPair localStatic, FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic, FfcEphemeralPublicKey remoteEphemeral);
    /// <inheritdoc cref="FfcSchemes.HybridOneFlowAsPartyU"/>
    byte[] HybridOneFlowAsPartyU(FfcStaticKeyPair localStatic, FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic);
    /// <inheritdoc cref="FfcSchemes.HybridOneFlowAsPartyV"/>
    byte[] HybridOneFlowAsPartyV(FfcStaticKeyPair localStatic, FfcStaticPublicKey remoteStatic, FfcEphemeralPublicKey remoteEphemeral);
    /// <inheritdoc cref="FfcSchemes.Mqv2"/>
    byte[] Mqv2(FfcStaticKeyPair localStatic, FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic, FfcEphemeralPublicKey remoteEphemeral);
    /// <inheritdoc cref="FfcSchemes.Mqv1AsPartyU"/>
    byte[] Mqv1AsPartyU(FfcStaticKeyPair localStatic, FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic);
    /// <inheritdoc cref="FfcSchemes.Mqv1AsPartyV"/>
    byte[] Mqv1AsPartyV(FfcStaticKeyPair localStatic, FfcStaticPublicKey remoteStatic, FfcEphemeralPublicKey remoteEphemeral);
}

/// <summary>The logging implementation of <see cref="IFfcKeyAgreement"/>. Stateless and thread-safe.</summary>
public sealed class FfcKeyAgreement(ILogger<FfcKeyAgreement>? logger = null) : IFfcKeyAgreement
{
    private readonly ILogger _logger = logger ?? NullLogger<FfcKeyAgreement>.Instance;

    /// <inheritdoc/>
    public byte[] Ephemeral(FfcEphemeralKeyPair localEphemeral, FfcEphemeralPublicKey remoteEphemeral)
    {
        try
        {
            byte[] z = FfcSchemes.Ephemeral(localEphemeral, remoteEphemeral);
            Log.Completed(_logger, "SP 800-56A", "FFC Ephemeral", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A FFC Ephemeral", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Static(FfcStaticKeyPair localStatic, FfcStaticPublicKey remoteStatic)
    {
        try
        {
            byte[] z = FfcSchemes.Static(localStatic, remoteStatic);
            Log.Completed(_logger, "SP 800-56A", "FFC Static", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A FFC Static", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] OneFlowAsPartyU(FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic)
    {
        try
        {
            byte[] z = FfcSchemes.OneFlowAsPartyU(localEphemeral, remoteStatic);
            Log.Completed(_logger, "SP 800-56A", "FFC OneFlowAsPartyU", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A FFC OneFlowAsPartyU", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] OneFlowAsPartyV(FfcStaticKeyPair localStatic, FfcEphemeralPublicKey remoteEphemeral)
    {
        try
        {
            byte[] z = FfcSchemes.OneFlowAsPartyV(localStatic, remoteEphemeral);
            Log.Completed(_logger, "SP 800-56A", "FFC OneFlowAsPartyV", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A FFC OneFlowAsPartyV", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Hybrid(FfcStaticKeyPair localStatic, FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic, FfcEphemeralPublicKey remoteEphemeral)
    {
        try
        {
            byte[] z = FfcSchemes.Hybrid(localStatic, localEphemeral, remoteStatic, remoteEphemeral);
            Log.Completed(_logger, "SP 800-56A", "FFC Hybrid", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A FFC Hybrid", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] HybridOneFlowAsPartyU(FfcStaticKeyPair localStatic, FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic)
    {
        try
        {
            byte[] z = FfcSchemes.HybridOneFlowAsPartyU(localStatic, localEphemeral, remoteStatic);
            Log.Completed(_logger, "SP 800-56A", "FFC HybridOneFlowAsPartyU", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A FFC HybridOneFlowAsPartyU", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] HybridOneFlowAsPartyV(FfcStaticKeyPair localStatic, FfcStaticPublicKey remoteStatic, FfcEphemeralPublicKey remoteEphemeral)
    {
        try
        {
            byte[] z = FfcSchemes.HybridOneFlowAsPartyV(localStatic, remoteStatic, remoteEphemeral);
            Log.Completed(_logger, "SP 800-56A", "FFC HybridOneFlowAsPartyV", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A FFC HybridOneFlowAsPartyV", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Mqv2(FfcStaticKeyPair localStatic, FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic, FfcEphemeralPublicKey remoteEphemeral)
    {
        try
        {
            byte[] z = FfcSchemes.Mqv2(localStatic, localEphemeral, remoteStatic, remoteEphemeral);
            Log.Completed(_logger, "SP 800-56A", "FFC Mqv2", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A FFC Mqv2", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Mqv1AsPartyU(FfcStaticKeyPair localStatic, FfcEphemeralKeyPair localEphemeral, FfcStaticPublicKey remoteStatic)
    {
        try
        {
            byte[] z = FfcSchemes.Mqv1AsPartyU(localStatic, localEphemeral, remoteStatic);
            Log.Completed(_logger, "SP 800-56A", "FFC Mqv1AsPartyU", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A FFC Mqv1AsPartyU", ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Mqv1AsPartyV(FfcStaticKeyPair localStatic, FfcStaticPublicKey remoteStatic, FfcEphemeralPublicKey remoteEphemeral)
    {
        try
        {
            byte[] z = FfcSchemes.Mqv1AsPartyV(localStatic, remoteStatic, remoteEphemeral);
            Log.Completed(_logger, "SP 800-56A", "FFC Mqv1AsPartyV", z.Length * 8L);
            return z;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, "SP 800-56A FFC Mqv1AsPartyV", ex))
        {
            throw;
        }
    }
}
