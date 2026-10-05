// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Internal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kdf108;

/// <summary>SP 800-108 key derivation as an injectable service. Mirrors <see cref="Sp800108"/>; inject it, or construct <see cref="Sp800108Kdf"/> directly.</summary>
public interface ISp800108Kdf
{
    /// <inheritdoc cref="Sp800108.Derive(ReadOnlySpan{byte}, Prf, ReadOnlySpan{byte}, ReadOnlySpan{byte}, BitLength)"/>
    byte[] Derive(ReadOnlySpan<byte> keyDerivationKey, Prf prf, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, BitLength length);

    /// <inheritdoc cref="Sp800108.Derive(ReadOnlySpan{byte}, Prf, KeyExpansion, BitLength)"/>
    byte[] Derive(ReadOnlySpan<byte> keyDerivationKey, Prf prf, KeyExpansion expansion, BitLength length);

    /// <inheritdoc cref="Sp800108.DeriveKmac"/>
    byte[] DeriveKmac(ReadOnlySpan<byte> keyDerivationKey, KmacVariant variant, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, BitLength length);
}

/// <summary>SP 800-56C key derivation as an injectable service. Mirrors <see cref="Sp80056C"/>; inject it, or construct <see cref="Sp80056CKdf"/> directly.</summary>
public interface ISp80056CKdf
{
    /// <inheritdoc cref="Sp80056C.OneStep"/>
    byte[] OneStep(ReadOnlySpan<byte> sharedSecret, OneStepFunction function, ReadOnlySpan<byte> fixedInfo, BitLength length, SecurityStrength strength);

    /// <inheritdoc cref="Sp80056C.Extract"/>
    byte[] Extract(ReadOnlySpan<byte> sharedSecret, Extraction extraction, SecurityStrength strength);

    /// <inheritdoc cref="Sp80056C.TwoStep"/>
    byte[] TwoStep(ReadOnlySpan<byte> sharedSecret, Extraction extraction, KeyExpansion expansion, BitLength length, SecurityStrength strength);
}

/// <summary>SP 800-56A key confirmation as an injectable service. Mirrors <see cref="KeyConfirmation"/>; inject it, or construct <see cref="KeyConfirmationService"/> directly.</summary>
public interface IKeyConfirmation
{
    /// <inheritdoc cref="KeyConfirmation.GenerateTag"/>
    byte[] GenerateTag(ReadOnlySpan<byte> macKey, KeyConfirmationContext context, KeyConfirmationMac mac, BitLength tagLength, SecurityStrength strength);

    /// <inheritdoc cref="KeyConfirmation.VerifyTag"/>
    bool VerifyTag(ReadOnlySpan<byte> receivedTag, ReadOnlySpan<byte> macKey, KeyConfirmationContext context, KeyConfirmationMac mac, BitLength tagLength, SecurityStrength strength);
}

/// <summary>The logging implementation of <see cref="ISp800108Kdf"/>. Stateless and thread-safe.</summary>
public sealed class Sp800108Kdf(ILogger<Sp800108Kdf>? logger = null) : ISp800108Kdf
{
    private const string Operation = "SP 800-108";
    private readonly ILogger _logger = logger ?? NullLogger<Sp800108Kdf>.Instance;

    /// <inheritdoc/>
    public byte[] Derive(ReadOnlySpan<byte> keyDerivationKey, Prf prf, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, BitLength length)
    {
        try
        {
            byte[] output = Sp800108.Derive(keyDerivationKey, prf, label, context, length);
            Log.Completed(_logger, Operation, $"{prf} counter mode", length.Bits);
            return output;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, Operation, ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Derive(ReadOnlySpan<byte> keyDerivationKey, Prf prf, KeyExpansion expansion, BitLength length)
    {
        try
        {
            byte[] output = Sp800108.Derive(keyDerivationKey, prf, expansion, length);
            Log.Completed(_logger, Operation, $"{prf} {expansion?.Mode} mode", length.Bits);
            return output;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, Operation, ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] DeriveKmac(ReadOnlySpan<byte> keyDerivationKey, KmacVariant variant, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, BitLength length)
    {
        try
        {
            byte[] output = Sp800108.DeriveKmac(keyDerivationKey, variant, label, context, length);
            Log.Completed(_logger, Operation, variant.ToString(), length.Bits);
            return output;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, Operation, ex))
        {
            throw;
        }
    }
}

/// <summary>The logging implementation of <see cref="ISp80056CKdf"/>. Stateless and thread-safe.</summary>
public sealed class Sp80056CKdf(ILogger<Sp80056CKdf>? logger = null) : ISp80056CKdf
{
    private const string Operation = "SP 800-56C";
    private readonly ILogger _logger = logger ?? NullLogger<Sp80056CKdf>.Instance;

    /// <inheritdoc/>
    public byte[] OneStep(ReadOnlySpan<byte> sharedSecret, OneStepFunction function, ReadOnlySpan<byte> fixedInfo, BitLength length, SecurityStrength strength)
    {
        try
        {
            byte[] output = Sp80056C.OneStep(sharedSecret, function, fixedInfo, length, strength);
            Log.Completed(_logger, Operation, $"one-step {function}", length.Bits);
            return output;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, Operation, ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] Extract(ReadOnlySpan<byte> sharedSecret, Extraction extraction, SecurityStrength strength)
    {
        try
        {
            byte[] output = Sp80056C.Extract(sharedSecret, extraction, strength);
            Log.Completed(_logger, Operation, $"extract {extraction}", output.Length * 8L);
            return output;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, Operation, ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] TwoStep(ReadOnlySpan<byte> sharedSecret, Extraction extraction, KeyExpansion expansion, BitLength length, SecurityStrength strength)
    {
        try
        {
            byte[] output = Sp80056C.TwoStep(sharedSecret, extraction, expansion, length, strength);
            Log.Completed(_logger, Operation, $"two-step {extraction} then {extraction?.ExpansionPrf} {expansion?.Mode} mode", length.Bits);
            return output;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, Operation, ex))
        {
            throw;
        }
    }
}

/// <summary>The logging implementation of <see cref="IKeyConfirmation"/>. Stateless and thread-safe.</summary>
public sealed class KeyConfirmationService(ILogger<KeyConfirmationService>? logger = null) : IKeyConfirmation
{
    private const string Operation = "SP 800-56A key confirmation";
    private readonly ILogger _logger = logger ?? NullLogger<KeyConfirmationService>.Instance;

    /// <inheritdoc/>
    public byte[] GenerateTag(ReadOnlySpan<byte> macKey, KeyConfirmationContext context, KeyConfirmationMac mac, BitLength tagLength, SecurityStrength strength)
    {
        try
        {
            byte[] tag = KeyConfirmation.GenerateTag(macKey, context, mac, tagLength, strength);
            Log.Completed(_logger, Operation, $"{mac} tag", tagLength.Bits);
            return tag;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, Operation, ex))
        {
            throw;
        }
    }

    /// <inheritdoc/>
    public bool VerifyTag(ReadOnlySpan<byte> receivedTag, ReadOnlySpan<byte> macKey, KeyConfirmationContext context, KeyConfirmationMac mac, BitLength tagLength, SecurityStrength strength)
    {
        try
        {
            bool verified = KeyConfirmation.VerifyTag(receivedTag, macKey, context, mac, tagLength, strength);
            if (verified) Log.Completed(_logger, Operation, $"{mac} tag verified", tagLength.Bits);
            else Log.TagMismatch(_logger, mac.ToString());
            return verified;
        }
        catch (Kdf108Exception ex) when (Log.Rejected(_logger, Operation, ex))
        {
            throw;
        }
    }
}

/// <summary>Registers the Kdf108 services with a dependency-injection container.</summary>
public static class Kdf108ServiceCollectionExtensions
{
    /// <summary>
    /// Adds <see cref="ISp800108Kdf"/>, <see cref="ISp80056CKdf"/>, <see cref="IEcKeyAgreement"/>,
    /// <see cref="IFfcKeyAgreement"/>, and <see cref="IKeyConfirmation"/> as singletons. Existing
    /// registrations are kept, so you can replace any of them.
    /// </summary>
    public static IServiceCollection AddKdf108(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        services.TryAddSingleton<ISp800108Kdf, Sp800108Kdf>();
        services.TryAddSingleton<ISp80056CKdf, Sp80056CKdf>();
        services.TryAddSingleton<IEcKeyAgreement, EcKeyAgreement>();
        services.TryAddSingleton<IFfcKeyAgreement, FfcKeyAgreement>();
        services.TryAddSingleton<IKeyConfirmation, KeyConfirmationService>();
        return services;
    }
}
