// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Kdf108.Domain.Sp80056A;
using Kdf108.Domain.Sp80056C;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Parameters;

namespace Kdf108.Simple;

/// <summary>
/// Simplified interface for common cryptographic key derivation operations.
/// This class provides an easy-to-use API that implements NIST SP 800-108 and SP 800-56A/C standards
/// with sensible defaults for common use cases.
/// </summary>
public static class SecureKeyDerivation
{
    /// <summary>
    /// Derives a key using HMAC-SHA256 counter mode key derivation function (NIST SP 800-108).
    /// </summary>
    /// <param name="masterKey">The master key material used for derivation.</param>
    /// <param name="purpose">A string describing the purpose of the derived key (used as label).</param>
    /// <param name="outputBytes">The desired output length in bytes. Default is 32 bytes (256 bits).</param>
    /// <param name="context">Optional context data for additional input. If null, empty array is used.</param>
    /// <param name="logger">Optional logger for operation logging.</param>
    /// <returns>The derived key material.</returns>
    /// <exception cref="ArgumentNullException">Thrown when masterKey or purpose is null.</exception>
    /// <exception cref="ArgumentException">Thrown when outputBytes is less than 1.</exception>
    public static byte[] DeriveKey(
        byte[] masterKey, 
        string purpose, 
        int outputBytes = 32,
        byte[]? context = null,
        ILogger? logger = null)
    {
        if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));
        if (string.IsNullOrEmpty(purpose)) throw new ArgumentNullException(nameof(purpose));
        if (outputBytes < 1) throw new ArgumentException("Output length must be at least 1 byte", nameof(outputBytes));

        logger?.LogDebug("Deriving key with purpose: {Purpose}, output length: {OutputBytes} bytes", purpose, outputBytes);

        var options = KdfOptions.CreateBuilder()
            .WithPrfType(PrfType.HmacSha256)
            .WithCounterLengthBits(32)
            .WithUseCounter(true)
            .WithCounterLocation(CounterLocation.BeforeFixed)
            .Build();

        var kdf = new CounterModeKdf(logger as ILogger<CounterModeKdf>);
        var result = kdf.DeriveKey(
            masterKey,
            purpose,
            context ?? Array.Empty<byte>(),
            outputBytes * 8L, // Convert to bits
            options);

        logger?.LogInformation("Successfully derived key for purpose: {Purpose}", purpose);
        return result;
    }

    /// <summary>
    /// Performs ECDH key agreement and derives keys using the shared secret (NIST SP 800-56A + SP 800-108).
    /// Uses P-256 curve by default.
    /// </summary>
    /// <param name="privateKey">The local EC private key parameters.</param>
    /// <param name="publicKey">The remote EC public key parameters.</param>
    /// <param name="purpose">A string describing the purpose of the derived key.</param>
    /// <param name="outputBytes">The desired output length in bytes. Default is 32 bytes (256 bits).</param>
    /// <param name="salt">Optional salt value for additional security. If null, no salt is used.</param>
    /// <param name="logger">Optional logger for operation logging.</param>
    /// <returns>The derived key material.</returns>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
    /// <exception cref="ArgumentException">Thrown when keys are invalid or incompatible.</exception>
    public static byte[] DeriveSharedKey(
        ECPrivateKeyParameters privateKey,
        ECPublicKeyParameters publicKey,
        string purpose,
        int outputBytes = 32,
        byte[]? salt = null,
        ILogger? logger = null)
    {
        if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
        if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
        if (string.IsNullOrEmpty(purpose)) throw new ArgumentNullException(nameof(purpose));
        if (outputBytes < 1) throw new ArgumentException("Output length must be at least 1 byte", nameof(outputBytes));

        logger?.LogDebug("Starting ECDH key agreement for purpose: {Purpose}", purpose);

        // Verify keys are on the same curve
        if (!privateKey.Parameters.Equals(publicKey.Parameters))
        {
            throw new ArgumentException("Private and public keys must be on the same curve");
        }

        // Create SP 800-56A private/public keys
        var sp56aPrivateKey = Sp80056APrivateKey.FromBouncyCastleParameters(privateKey, "P-256");
        var sp56aPublicKey = Sp80056APublicKey.FromBouncyCastleParameters(publicKey, "P-256");

        // Create ECDH key agreement
        var ecdh = Sp80056AEcdhKeyAgreement.CreateP256(logger as ILogger<Sp80056AEcdhKeyAgreement>);

        // Create SP 800-56C pipeline options
        var builder = Sp80056COptions.CreateBuilder()
            .WithLabel(purpose)
            .WithOutputLengthInBytes(outputBytes)
            .UseOneStepKdf(PrfType.HmacSha256)
            .WithKdfMode(KdfMode.Counter)
            .WithCounterConfiguration(32, CounterLocation.BeforeFixed);
            
        if (salt != null)
        {
            builder.WithSalt(salt);
        }
        
        var pipelineOptions = builder.Build();

        // Create one-step KDF pipeline
        var pipeline = new Sp80056COneStepKdf(ecdh, logger as ILogger<Sp80056COneStepKdf>);

        // Derive key
        var result = pipeline.DeriveKey(sp56aPrivateKey, sp56aPublicKey, pipelineOptions);

        logger?.LogInformation("Successfully derived shared key using ECDH + KDF for purpose: {Purpose}", purpose);
        return result;
    }

    /// <summary>
    /// Establishes a complete secure channel with separate encryption and MAC keys using ECDH + KDF.
    /// This method performs ECDH key agreement and derives multiple keys for different purposes.
    /// </summary>
    /// <param name="localPrivate">The local EC private key parameters.</param>
    /// <param name="remotePublic">The remote EC public key parameters.</param>
    /// <param name="salt">Optional salt value. If null, a zero salt is used.</param>
    /// <param name="logger">Optional logger for operation logging.</param>
    /// <returns>A SecureChannelKeys object containing encryption key, MAC key, and IV.</returns>
    /// <exception cref="ArgumentNullException">Thrown when required parameters are null.</exception>
    public static SecureChannelKeys EstablishSecureChannel(
        ECPrivateKeyParameters localPrivate,
        ECPublicKeyParameters remotePublic,
        byte[]? salt = null,
        ILogger? logger = null)
    {
        if (localPrivate == null) throw new ArgumentNullException(nameof(localPrivate));
        if (remotePublic == null) throw new ArgumentNullException(nameof(remotePublic));

        logger?.LogInformation("Establishing secure channel");

        // Create SP 800-56A private/public keys
        var sp56aPrivateKey = Sp80056APrivateKey.FromBouncyCastleParameters(localPrivate, "P-256");
        var sp56aPublicKey = Sp80056APublicKey.FromBouncyCastleParameters(remotePublic, "P-256");

        // Create ECDH key agreement
        var ecdh = Sp80056AEcdhKeyAgreement.CreateP256(logger as ILogger<Sp80056AEcdhKeyAgreement>);

        // Derive keys for different purposes
        var actualSalt = salt ?? new byte[32]; // Default to zero salt

        // Derive encryption key (256 bits)
        var encOptions = Sp80056COptions.CreateBuilder()
            .WithLabel("ENCRYPTION")
            .WithOutputLengthInBytes(32)
            .WithSalt(actualSalt)
            .WithContext(new byte[] { 0x01 }) // Different context for each key
            .UseOneStepKdf(PrfType.HmacSha256)
            .WithKdfMode(KdfMode.Counter)
            .Build();

        var pipeline = new Sp80056COneStepKdf(ecdh, logger as ILogger<Sp80056COneStepKdf>);
        var encryptionKey = pipeline.DeriveKey(sp56aPrivateKey, sp56aPublicKey, encOptions);

        // Derive MAC key (256 bits)
        var macOptions = Sp80056COptions.CreateBuilder()
            .WithLabel("MAC")
            .WithOutputLengthInBytes(32)
            .WithSalt(actualSalt)
            .WithContext(new byte[] { 0x02 })
            .UseOneStepKdf(PrfType.HmacSha256)
            .WithKdfMode(KdfMode.Counter)
            .Build();

        var macKey = pipeline.DeriveKey(sp56aPrivateKey, sp56aPublicKey, macOptions);

        // Derive IV (128 bits)
        var ivOptions = Sp80056COptions.CreateBuilder()
            .WithLabel("IV")
            .WithOutputLengthInBytes(16)
            .WithSalt(actualSalt)
            .WithContext(new byte[] { 0x03 })
            .UseOneStepKdf(PrfType.HmacSha256)
            .WithKdfMode(KdfMode.Counter)
            .Build();

        var iv = pipeline.DeriveKey(sp56aPrivateKey, sp56aPublicKey, ivOptions);

        logger?.LogInformation("Successfully established secure channel with encryption key, MAC key, and IV");

        return new SecureChannelKeys
        {
            EncryptionKey = encryptionKey,
            MacKey = macKey,
            Iv = iv
        };
    }

    /// <summary>
    /// Derives a key using the specified PRF type and mode with full control over parameters.
    /// This is for advanced users who need specific configurations.
    /// </summary>
    /// <param name="masterKey">The master key material.</param>
    /// <param name="purpose">The purpose/label for the derived key.</param>
    /// <param name="outputBytes">The desired output length in bytes.</param>
    /// <param name="options">A builder action to configure KDF options.</param>
    /// <param name="mode">The KDF mode to use. Default is Counter.</param>
    /// <param name="logger">Optional logger for operation logging.</param>
    /// <returns>The derived key material.</returns>
    public static byte[] DeriveKeyAdvanced(
        byte[] masterKey,
        string purpose,
        int outputBytes,
        Action<KdfOptionsBuilder> options,
        KdfMode mode = KdfMode.Counter,
        ILogger? logger = null)
    {
        if (masterKey == null) throw new ArgumentNullException(nameof(masterKey));
        if (string.IsNullOrEmpty(purpose)) throw new ArgumentNullException(nameof(purpose));
        if (outputBytes < 1) throw new ArgumentException("Output length must be at least 1 byte", nameof(outputBytes));
        if (options == null) throw new ArgumentNullException(nameof(options));

        var builder = KdfOptions.CreateBuilder();
        options(builder);
        var kdfOptions = builder.Build();

        logger?.LogDebug("Advanced key derivation with mode: {Mode}, PRF: {PrfType}", mode, kdfOptions.PrfType);

        var engine = new KdfEngine();
        return engine.Derive(
            mode,
            masterKey,
            purpose,
            Array.Empty<byte>(),
            outputBytes * 8L, // Convert to bits
            kdfOptions);
    }
}

/// <summary>
/// Contains the keys derived for establishing a secure channel.
/// </summary>
public class SecureChannelKeys
{
    /// <summary>
    /// The encryption key for the secure channel.
    /// </summary>
    public byte[] EncryptionKey { get; init; } = Array.Empty<byte>();

    /// <summary>
    /// The MAC (Message Authentication Code) key for the secure channel.
    /// </summary>
    public byte[] MacKey { get; init; } = Array.Empty<byte>();

    /// <summary>
    /// The initialization vector for the secure channel encryption.
    /// </summary>
    public byte[] Iv { get; init; } = Array.Empty<byte>();
}
