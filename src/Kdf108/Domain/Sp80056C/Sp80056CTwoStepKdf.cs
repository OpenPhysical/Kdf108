// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.IO;
using System.Security.Cryptography;
using Kdf108.Domain.Interfaces.KeyAgreement;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Sp80056A;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kdf108.Domain.Sp80056C;

/// <summary>
/// Implements the two-step key derivation method as defined in NIST SP 800-56C.
/// This method uses an extraction step followed by an expansion step (similar to HKDF).
/// </summary>
internal class Sp80056CTwoStepKdf : ISp80056CKeyDerivationPipeline
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
            try
            {
                return DeriveKeyFromSharedSecret(sharedSecret, options);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sharedSecret);
            }
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
            var extraction = CreateExtraction(options.ExtractionPrfType, options.Salt);
            EnsurePermittedExpansion(options.ExtractionPrfType, options.ExpansionPrfType);
            var fixedInfo = options.OtherInfo ?? CreateLegacyFixedInfo(
                options.Label,
                options.Context,
                options.OutputLengthInBits);
            var outputLength = BitLength.Create(options.OutputLengthInBits);
            KeyExpansion expansion = options.KdfMode switch
            {
                KdfMode.Counter => KeyExpansion.CounterMode(fixedInfo, outputLength, options.CounterLengthBits, options.CounterLocation),
                KdfMode.Feedback => KeyExpansion.FeedbackMode(fixedInfo, Array.Empty<byte>(), outputLength, false, options.CounterLengthBits, options.CounterLocation),
                KdfMode.FeedbackWithCounter => KeyExpansion.FeedbackMode(fixedInfo, Array.Empty<byte>(), outputLength, true, options.CounterLengthBits, options.CounterLocation),
                KdfMode.DoublePipeline => KeyExpansion.DoublePipelineMode(fixedInfo, outputLength, false, options.CounterLengthBits, options.CounterLocation),
                KdfMode.DoublePipelineWithCounter => KeyExpansion.DoublePipelineMode(fixedInfo, outputLength, true, options.CounterLengthBits, options.CounterLocation),
                _ => throw new ArgumentOutOfRangeException(nameof(options.KdfMode))
            };
            var request = new TwoStepKdfRequest(
                sharedSecret,
                extraction,
                SecurityStrength.Bits112,
                new[] { expansion });
            var expandedKey = Sp80056CTwoStep.Derive(request)[0];
            _logger.LogInformation("Successfully derived key using two-step KDF, output length: {Length} bits", 
                options.OutputLengthInBits);

            return expandedKey;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in two-step key derivation from shared secret");
            throw;
        }
    }

    private static TwoStepExtraction CreateExtraction(PrfType type, byte[]? salt) => type switch
    {
        PrfType.HmacSha1 => TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha1, salt ?? Array.Empty<byte>()),
        PrfType.HmacSha224 => TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha224, salt ?? Array.Empty<byte>()),
        PrfType.HmacSha256 => TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha256, salt ?? Array.Empty<byte>()),
        PrfType.HmacSha384 => TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha384, salt ?? Array.Empty<byte>()),
        PrfType.HmacSha512 => TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha512, salt ?? Array.Empty<byte>()),
        PrfType.HmacSha512_224 => TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha512_224, salt ?? Array.Empty<byte>()),
        PrfType.HmacSha512_256 => TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha512_256, salt ?? Array.Empty<byte>()),
        PrfType.HmacSha3_224 => TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha3_224, salt ?? Array.Empty<byte>()),
        PrfType.HmacSha3_256 => TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha3_256, salt ?? Array.Empty<byte>()),
        PrfType.HmacSha3_384 => TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha3_384, salt ?? Array.Empty<byte>()),
        PrfType.HmacSha3_512 => TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha3_512, salt ?? Array.Empty<byte>()),
        PrfType.CmacAes128 => TwoStepExtraction.AesCmacFunction(128, salt ?? Array.Empty<byte>()),
        PrfType.CmacAes192 => TwoStepExtraction.AesCmacFunction(192, salt ?? Array.Empty<byte>()),
        PrfType.CmacAes256 => TwoStepExtraction.AesCmacFunction(256, salt ?? Array.Empty<byte>()),
        _ => throw new ArgumentException("SP 800-56C two-step extraction requires HMAC or AES-CMAC.", nameof(type))
    };

    private static void EnsurePermittedExpansion(PrfType extraction, PrfType expansion)
    {
        bool permitted = extraction switch
        {
            PrfType.CmacAes128 or PrfType.CmacAes192 or PrfType.CmacAes256 => expansion == PrfType.CmacAes128,
            _ => extraction == expansion
        };
        if (!permitted)
            throw new ArgumentException("The expansion PRF is not permitted for the selected extraction MAC.", nameof(expansion));
    }

    private static byte[] CreateLegacyFixedInfo(string label, byte[] context, long outputLengthBits)
    {
        using var stream = new MemoryStream();
        stream.Write(KdfLabel.FromString(label).ToArray());
        stream.WriteByte(0);
        stream.Write(context);
        stream.WriteByte((byte)(outputLengthBits >> 24));
        stream.WriteByte((byte)(outputLengthBits >> 16));
        stream.WriteByte((byte)(outputLengthBits >> 8));
        stream.WriteByte((byte)outputLengthBits);
        return stream.ToArray();
    }

    /// <inheritdoc/>
    public string PipelineName => $"SP800-56C-TwoStep-{_keyAgreement.SchemeName}";

}
