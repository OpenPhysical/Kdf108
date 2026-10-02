// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Domain.Interfaces.KeyAgreement;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Sp80056A;
using Kdf108.Infrastructure.Prf;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kdf108.Domain.Sp80056C;

/// <summary>
/// Implements the two-step key derivation method as defined in NIST SP 800-56C.
/// This method uses an extraction step followed by an expansion step (similar to HKDF).
/// </summary>
public class Sp80056CTwoStepKdf : ISp80056CKeyDerivationPipeline
{
    private readonly ILogger<Sp80056CTwoStepKdf> _logger;
    private readonly ISp80056AKeyAgreement _keyAgreement;

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056CTwoStepKdf"/> class.
    /// </summary>
    /// <param name="keyAgreement">The key agreement implementation to use.</param>
    /// <param name="logger">Optional logger instance.</param>
    public Sp80056CTwoStepKdf(ISp80056AKeyAgreement keyAgreement, ILogger<Sp80056CTwoStepKdf>? logger = null)
    {
        _keyAgreement = keyAgreement ?? throw new ArgumentNullException(nameof(keyAgreement));
        _logger = logger ?? NullLogger<Sp80056CTwoStepKdf>.Instance;
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

        _logger.LogDebug("Starting two-step key derivation with {KeyAgreementScheme}", _keyAgreement.SchemeName);

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
            _logger.LogError(ex, "Error in two-step key derivation");
            throw;
        }
    }

    /// <inheritdoc/>
    public byte[] DeriveKeyFromSharedSecret(byte[] sharedSecret, Sp80056COptions options)
    {
        if (sharedSecret == null) throw new ArgumentNullException(nameof(sharedSecret));
        if (options == null) throw new ArgumentNullException(nameof(options));

        _logger.LogDebug("Starting two-step derivation: Extract with {ExtractPrf}, Expand with {ExpandPrf}", 
            options.ExtractionPrfType, options.ExpansionPrfType);

        try
        {
            // Step 1: Extract - derive a key-derivation key from the shared secret
            var extractedKey = PerformExtraction(sharedSecret, options);
            _logger.LogDebug("Extraction completed, extracted key size: {Size} bytes", extractedKey.Length);

            // Step 2: Expand - use the extracted key to derive the final key material
            var expandedKey = PerformExpansion(extractedKey, options);
            _logger.LogInformation("Successfully derived key using two-step KDF, output length: {Length} bits", 
                options.OutputLengthInBits);

            // Clear sensitive material
            Array.Clear(extractedKey, 0, extractedKey.Length);

            return expandedKey;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in two-step key derivation from shared secret");
            throw;
        }
    }

    /// <inheritdoc/>
    public string PipelineName => $"SP800-56C-TwoStep-{_keyAgreement.SchemeName}";

    /// <summary>
    /// Performs the extraction step of the two-step KDF.
    /// </summary>
    /// <param name="sharedSecret">The shared secret from key agreement.</param>
    /// <param name="options">Pipeline configuration options.</param>
    /// <returns>The extracted key material.</returns>
    private byte[] PerformExtraction(byte[] sharedSecret, Sp80056COptions options)
    {
        var extractionPrf = PrfFactory.Create(options.ExtractionPrfType);
        
        // Use salt if provided, otherwise use a zero key of PRF output size
        var salt = options.Salt;
        if (salt == null || salt.Length == 0)
        {
            salt = new byte[extractionPrf.OutputSizeBits / 8];
            _logger.LogDebug("No salt provided, using zero salt of {Size} bytes", salt.Length);
        }

        // The extraction step uses the salt as the key and shared secret as the message
        var extractedKey = extractionPrf.Compute(salt, sharedSecret);
        
        return extractedKey;
    }

    /// <summary>
    /// Performs the expansion step of the two-step KDF.
    /// </summary>
    /// <param name="extractedKey">The key material from the extraction step.</param>
    /// <param name="options">Pipeline configuration options.</param>
    /// <returns>The expanded key material.</returns>
    private byte[] PerformExpansion(byte[] extractedKey, Sp80056COptions options)
    {
        // Build KDF options for expansion
        var kdfOptions = KdfOptions.CreateBuilder()
            .WithPrfType(options.ExpansionPrfType)
            .WithCounterLengthBits(options.CounterLengthBits)
            .WithUseCounter(true)
            .WithCounterLocation(options.CounterLocation)
            .Build();

        // If OtherInfo is provided, use it as context
        var context = options.OtherInfo ?? options.Context;

        // Perform key expansion using SP 800-108
        var kdfEngine = new KdfEngine();
        return kdfEngine.Derive(
            options.KdfMode,
            extractedKey,
            options.Label,
            context,
            options.OutputLengthInBits,
            kdfOptions);
    }
}
