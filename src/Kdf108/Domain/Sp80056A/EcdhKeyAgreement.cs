// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Linq;
using Kdf108.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Math;

namespace Kdf108.Domain.Sp80056A;

/// <summary>
/// Provides ECDH (Elliptic Curve Diffie-Hellman) key agreement operations
/// as specified in NIST SP 800-56A.
/// </summary>
public static class EcdhKeyAgreement
{
    /// <summary>
    /// Computes ECDH shared secret using a full keypair.
    /// This is the most common case - you have a validated keypair.
    /// </summary>
    /// <param name="localKeyPair">The local key pair.</param>
    /// <param name="remotePublicKey">The remote party's public key.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <returns>The computed shared secret.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="KeyAgreementException">Thrown when curves don't match or agreement fails.</exception>
    public static SharedSecret ComputeSharedSecret(
        EcKeyPair localKeyPair,
        EcPublicKey remotePublicKey,
        ILogger? logger = null)
    {
        if (localKeyPair == null) throw new ArgumentNullException(nameof(localKeyPair));
        if (remotePublicKey == null) throw new ArgumentNullException(nameof(remotePublicKey));
        
        // Use the private key from the keypair
        return ComputeSharedSecret(localKeyPair.PrivateKey, remotePublicKey, logger);
    }
    
    /// <summary>
    /// Computes ECDH shared secret using only a private key.
    /// Use this when you don't have/need the full keypair.
    /// </summary>
    /// <param name="localPrivateKey">The local private key.</param>
    /// <param name="remotePublicKey">The remote party's public key.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <returns>The computed shared secret.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="KeyAgreementException">Thrown when curves don't match or agreement fails.</exception>
    public static SharedSecret ComputeSharedSecret(
        EcPrivateKey localPrivateKey,
        EcPublicKey remotePublicKey,
        ILogger? logger = null)
    {
        if (localPrivateKey == null) throw new ArgumentNullException(nameof(localPrivateKey));
        if (remotePublicKey == null) throw new ArgumentNullException(nameof(remotePublicKey));
        
        var internalLogger = logger ?? NullLogger.Instance;
        
        // Curves must match
        if (!localPrivateKey.CurveName.Equals(remotePublicKey.CurveName, StringComparison.Ordinal))
        {
            throw new KeyAgreementException(
                $"Curve mismatch: local uses {localPrivateKey.CurveName}, remote uses {remotePublicKey.CurveName}");
        }
        
        if (internalLogger.IsEnabled(LogLevel.Debug))
            internalLogger.LogDebug("Computing ECDH shared secret on curve {Curve}", localPrivateKey.CurveName);
        
        try
        {
            // Keys are already validated at construction - just use them!
            var agreement = CreateAgreement(localPrivateKey.CurveName);
            agreement.Init(localPrivateKey.ToBouncyCastleParameters());
            
            var z = agreement.CalculateAgreement(remotePublicKey.ToBouncyCastleParameters());
            var sharedSecret = FormatSharedSecret(z, localPrivateKey.Parameters.Curve.FieldSize);
            
            if (internalLogger.IsEnabled(LogLevel.Debug))
                internalLogger.LogDebug("Successfully computed ECDH shared secret of {Length} bytes", sharedSecret.Length);
            
            return sharedSecret;
        }
        catch (Exception ex) when (ex is not CryptographicException)
        {
            internalLogger.LogError(ex, "Failed to compute ECDH shared secret");
            throw new KeyAgreementException("Failed to compute shared secret", ex);
        }
    }
    
    /// <summary>
    /// Computes ECDH ephemeral unified shared secret.
    /// This is an alias for clarity when using ephemeral keys.
    /// </summary>
    public static SharedSecret ComputeEphemeralUnified(
        EcKeyPair localEphemeral,
        EcPublicKey remoteEphemeral,
        ILogger? logger = null)
    {
        return ComputeSharedSecret(localEphemeral, remoteEphemeral, logger);
    }
    
    /// <summary>
    /// Computes ECDH static unified shared secret.
    /// This is an alias for clarity when using static keys.
    /// </summary>
    public static SharedSecret ComputeStaticUnified(
        EcKeyPair localStatic,
        EcPublicKey remoteStatic,
        ILogger? logger = null)
    {
        return ComputeSharedSecret(localStatic, remoteStatic, logger);
    }
    
    /// <summary>
    /// Computes ECDH full unified shared secret (Ze || Zs).
    /// Full unified always needs keypairs because you're using both static and ephemeral.
    /// </summary>
    public static SharedSecret ComputeFullUnified(
        EcKeyPair localStatic,
        EcKeyPair localEphemeral,
        EcPublicKey remoteStatic,
        EcPublicKey remoteEphemeral,
        ILogger? logger = null)
    {
        if (localStatic == null) throw new ArgumentNullException(nameof(localStatic));
        if (localEphemeral == null) throw new ArgumentNullException(nameof(localEphemeral));
        if (remoteStatic == null) throw new ArgumentNullException(nameof(remoteStatic));
        if (remoteEphemeral == null) throw new ArgumentNullException(nameof(remoteEphemeral));
        
        // Validate all curves match
        var curves = new[] 
        { 
            localStatic.CurveName, 
            localEphemeral.CurveName, 
            remoteStatic.CurveName, 
            remoteEphemeral.CurveName 
        };
        
        if (curves.Distinct().Count() > 1)
        {
            throw new KeyAgreementException("All keys must use the same curve for full unified agreement");
        }
        
        var internalLogger = logger ?? NullLogger.Instance;
        
        if (internalLogger.IsEnabled(LogLevel.Debug))
            internalLogger.LogDebug("Computing ECDH full unified shared secret on curve {Curve}", localStatic.CurveName);
        
        // Compute Ze || Zs
        var ze = ComputeSharedSecret(localEphemeral, remoteEphemeral, logger);
        var zs = ComputeSharedSecret(localStatic, remoteStatic, logger);
        
        return SharedSecret.Concatenate(ze, zs);
    }
    
    /// <summary>
    /// Computes ECDH one-pass unified shared secret as initiator.
    /// Initiator has both static and ephemeral keys.
    /// </summary>
    public static SharedSecret ComputeOnePassUnifiedAsInitiator(
        EcKeyPair localStatic,
        EcKeyPair localEphemeral,
        EcPublicKey remoteStatic,
        ILogger? logger = null)
    {
        if (localStatic == null) throw new ArgumentNullException(nameof(localStatic));
        if (localEphemeral == null) throw new ArgumentNullException(nameof(localEphemeral));
        if (remoteStatic == null) throw new ArgumentNullException(nameof(remoteStatic));
        
        // Validate curves match
        if (!localStatic.CurveName.Equals(localEphemeral.CurveName, StringComparison.Ordinal) ||
            !localStatic.CurveName.Equals(remoteStatic.CurveName, StringComparison.Ordinal))
        {
            throw new KeyAgreementException("All keys must use the same curve for one-pass unified agreement");
        }
        
        var internalLogger = logger ?? NullLogger.Instance;
        
        if (internalLogger.IsEnabled(LogLevel.Debug))
            internalLogger.LogDebug("Computing ECDH one-pass unified shared secret as initiator on curve {Curve}", 
                localStatic.CurveName);
        
        // Ze = ECDH(deIUT, QsCAVS), Zs = ECDH(dsIUT, QsCAVS)
        var ze = ComputeSharedSecret(localEphemeral, remoteStatic, logger);
        var zs = ComputeSharedSecret(localStatic, remoteStatic, logger);
        
        return SharedSecret.Concatenate(ze, zs);
    }
    
    /// <summary>
    /// Computes ECDH one-pass unified shared secret as responder.
    /// Responder has only static key, remote has both.
    /// </summary>
    public static SharedSecret ComputeOnePassUnifiedAsResponder(
        EcKeyPair localStatic,
        EcPublicKey remoteStatic,
        EcPublicKey remoteEphemeral,
        ILogger? logger = null)
    {
        if (localStatic == null) throw new ArgumentNullException(nameof(localStatic));
        if (remoteStatic == null) throw new ArgumentNullException(nameof(remoteStatic));
        if (remoteEphemeral == null) throw new ArgumentNullException(nameof(remoteEphemeral));
        
        // Validate curves match
        if (!localStatic.CurveName.Equals(remoteStatic.CurveName, StringComparison.Ordinal) ||
            !localStatic.CurveName.Equals(remoteEphemeral.CurveName, StringComparison.Ordinal))
        {
            throw new KeyAgreementException("All keys must use the same curve for one-pass unified agreement");
        }
        
        var internalLogger = logger ?? NullLogger.Instance;
        
        if (internalLogger.IsEnabled(LogLevel.Debug))
            internalLogger.LogDebug("Computing ECDH one-pass unified shared secret as responder on curve {Curve}", 
                localStatic.CurveName);
        
        // Ze = ECDH(dsIUT, QeCAVS), Zs = ECDH(dsIUT, QsCAVS)
        var ze = ComputeSharedSecret(localStatic, remoteEphemeral, logger);
        var zs = ComputeSharedSecret(localStatic, remoteStatic, logger);
        
        return SharedSecret.Concatenate(ze, zs);
    }
    
    /// <summary>
    /// Computes ECDH one-pass DH shared secret.
    /// Only one ECDH operation with mixed static/ephemeral keys.
    /// </summary>
    public static SharedSecret ComputeOnePassDH(
        EcPrivateKey localKey,
        EcPublicKey remoteKey,
        ILogger? logger = null)
    {
        // This is just standard ECDH with a specific name for the scheme
        return ComputeSharedSecret(localKey, remoteKey, logger);
    }
    
    /// <summary>
    /// Computes ECDH one-pass DH shared secret using a keypair.
    /// </summary>
    public static SharedSecret ComputeOnePassDH(
        EcKeyPair localKeyPair,
        EcPublicKey remoteKey,
        ILogger? logger = null)
    {
        // This is just standard ECDH with a specific name for the scheme
        return ComputeSharedSecret(localKeyPair, remoteKey, logger);
    }
    
    private static IBasicAgreement CreateAgreement(string curveName)
    {
        // Binary curves need cofactor multiplication
        if (CurveRegistry.IsBinaryCurve(curveName))
        {
            return new ECDHCBasicAgreement();
        }
        return new ECDHBasicAgreement();
    }
    
    private static SharedSecret FormatSharedSecret(BigInteger z, int fieldSizeBits)
    {
        var sharedSecretBytes = z.ToByteArrayUnsigned();
        var expectedLength = (fieldSizeBits + 7) / 8; // Round up to nearest byte
        
        if (sharedSecretBytes.Length < expectedLength)
        {
            // Pad with zeros at the beginning
            var paddedSecret = new byte[expectedLength];
            Array.Copy(sharedSecretBytes, 0, paddedSecret, expectedLength - sharedSecretBytes.Length, sharedSecretBytes.Length);
            sharedSecretBytes = paddedSecret;
        }
        
        return new SharedSecret(sharedSecretBytes);
    }
}