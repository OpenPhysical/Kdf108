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
/// Implements the one-step key derivation method as defined in NIST SP 800-56C.
/// This method directly applies an approved KDF to the shared secret.
/// </summary>
internal class Sp80056COneStepKdf : ISp80056CKeyDerivationPipeline
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
            var fixedInfo = options.OtherInfo ?? CreateLegacyFixedInfo(
                options.Label,
                options.Context,
                options.OutputLengthInBits);
            var auxiliary = OneStepAuxiliaryFunction.HmacFunction(
                ToHashAlgorithm(options.ExpansionPrfType),
                options.Salt ?? Array.Empty<byte>());
            var request = new OneStepKdfRequest(
                sharedSecret,
                fixedInfo,
                BitLength.Create(options.OutputLengthInBits),
                SecurityStrength.Bits112,
                auxiliary);
            var derivedKey = Sp80056COneStep.Derive(request);

            _logger.LogInformation("Successfully derived key using one-step KDF, output length: {Length} bits", 
                options.OutputLengthInBits);

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

    private static NistHashAlgorithm ToHashAlgorithm(PrfType prfType) => prfType switch
    {
        PrfType.HmacSha1 => NistHashAlgorithm.Sha1,
        PrfType.HmacSha224 => NistHashAlgorithm.Sha224,
        PrfType.HmacSha256 => NistHashAlgorithm.Sha256,
        PrfType.HmacSha384 => NistHashAlgorithm.Sha384,
        PrfType.HmacSha512 => NistHashAlgorithm.Sha512,
        PrfType.HmacSha512_224 => NistHashAlgorithm.Sha512_224,
        PrfType.HmacSha512_256 => NistHashAlgorithm.Sha512_256,
        PrfType.HmacSha3_224 => NistHashAlgorithm.Sha3_224,
        PrfType.HmacSha3_256 => NistHashAlgorithm.Sha3_256,
        PrfType.HmacSha3_384 => NistHashAlgorithm.Sha3_384,
        PrfType.HmacSha3_512 => NistHashAlgorithm.Sha3_512,
        _ => throw new ArgumentException("One-step SP 800-56C requires a hash, HMAC, or KMAC auxiliary function.", nameof(prfType))
    };

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
}
