// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Domain.Interfaces.KeyAgreement;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Sp80056A;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kdf108.Domain.Sp80056C;

/// <summary>
/// Implements the one-step key derivation method as defined in NIST SP 800-56C.
/// This method directly applies an approved KDF to the shared secret.
/// </summary>
public class Sp80056COneStepKdf : ISp80056CKeyDerivationPipeline
{
    private readonly ILogger<Sp80056COneStepKdf> _logger;
    private readonly ISp80056AKeyAgreement _keyAgreement;

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056COneStepKdf"/> class.
    /// </summary>
    /// <param name="keyAgreement">The key agreement implementation to use.</param>
    /// <param name="logger">Optional logger instance.</param>
    public Sp80056COneStepKdf(ISp80056AKeyAgreement keyAgreement, ILogger<Sp80056COneStepKdf>? logger = null)
    {
        _keyAgreement = keyAgreement ?? throw new ArgumentNullException(nameof(keyAgreement));
        _logger = logger ?? NullLogger<Sp80056COneStepKdf>.Instance;
    }

    /// <inheritdoc/>
    public byte[] DeriveKey(
        Sp80056APrivateKey localPrivateKey,
        Sp80056APublicKey remotePublicKey,
        Sp80056COptions options)
    {
        if (localPrivateKey == null) throw new ArgumentNullException(nameof(localPrivateKey));
        if (remotePublicKey == null) throw new ArgumentNullException(nameof(remotePublicKey));
        if (options == null) throw new ArgumentNullException(nameof(options));

        _logger.LogDebug("Starting one-step key derivation with {KeyAgreementScheme}", _keyAgreement.SchemeName);

        try
        {
            // Validate that keys are on the same curve
            if (!localPrivateKey.DomainParameters.Equals(remotePublicKey.DomainParameters))
            {
                throw new ArgumentException("Private and public keys must use the same domain parameters");
            }

            // Perform key agreement
            var sharedSecret = _keyAgreement.PerformKeyAgreement(
                localPrivateKey.ToBytes(),
                remotePublicKey.ToBytes());

            _logger.LogDebug("Key agreement completed, shared secret size: {Size} bytes", sharedSecret.Length);

            // Derive key from shared secret
            return DeriveKeyFromSharedSecret(sharedSecret, options);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in one-step key derivation");
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] DeriveKeyFromSharedSecret(byte[] sharedSecret, Sp80056COptions options)
    {
        if (sharedSecret == null) throw new ArgumentNullException(nameof(sharedSecret));
        if (options == null) throw new ArgumentNullException(nameof(options));

        _logger.LogDebug("Deriving key from shared secret using {KdfMode} mode", options.KdfMode);

        try
        {
            // Build KDF options
            var kdfOptions = KdfOptions.CreateBuilder()
                .WithPrfType(options.ExpansionPrfType)
                .WithCounterLengthBits(options.CounterLengthBits)
                .WithUseCounter(true)
                .WithCounterLocation(options.CounterLocation)
                .Build();

            // Combine shared secret with salt if provided
            byte[] kdk;
            if (options.Salt != null && options.Salt.Length > 0)
            {
                kdk = new byte[sharedSecret.Length + options.Salt.Length];
                Buffer.BlockCopy(sharedSecret, 0, kdk, 0, sharedSecret.Length);
                Buffer.BlockCopy(options.Salt, 0, kdk, sharedSecret.Length, options.Salt.Length);
                _logger.LogDebug("Combined shared secret with salt, KDK size: {Size} bytes", kdk.Length);
            }
            else
            {
                kdk = sharedSecret;
            }

            // If OtherInfo is provided, use it as context
            var context = options.OtherInfo ?? options.Context;

            // Perform key derivation using SP 800-108
            var kdfEngine = new KdfEngine();
            var derivedKey = kdfEngine.Derive(
                options.KdfMode,
                kdk,
                options.Label,
                context,
                options.OutputLengthInBits,
                kdfOptions);

            _logger.LogInformation("Successfully derived key using one-step KDF, output length: {Length} bits", 
                options.OutputLengthInBits);

            // Clear sensitive material
            if (kdk != sharedSecret)
            {
                Array.Clear(kdk, 0, kdk.Length);
            }

            return derivedKey;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deriving key from shared secret");
            throw;
        }
    }

    /// <inheritdoc/>
    public string PipelineName => $"SP800-56C-OneStep-{_keyAgreement.SchemeName}";
}
