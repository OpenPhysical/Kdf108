// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Linq;
using Kdf108.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Kdf108.Domain.Sp80056A;

/// <summary>
/// Provides EC-MQV (Elliptic Curve Menezes-Qu-Vanstone) key agreement operations
/// as specified in NIST SP 800-56A.
/// </summary>
public static class EcMqvKeyAgreement
{
    /// <summary>
    /// Computes EC-MQV full shared secret using both static and ephemeral keys from both parties.
    /// </summary>
    /// <param name="localStatic">The local static key pair.</param>
    /// <param name="localEphemeral">The local ephemeral key pair.</param>
    /// <param name="remoteStatic">The remote party's static public key.</param>
    /// <param name="remoteEphemeral">The remote party's ephemeral public key.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <returns>The computed shared secret.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="KeyAgreementException">Thrown when curves don't match or agreement fails.</exception>
    public static SharedSecret ComputeFullMqv(
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
        
        // Validate curves
        var curves = new[] 
        { 
            localStatic.CurveName, 
            localEphemeral.CurveName, 
            remoteStatic.CurveName, 
            remoteEphemeral.CurveName 
        };
        
        if (curves.Distinct().Count() > 1)
        {
            throw new KeyAgreementException("All keys must use the same curve for MQV agreement");
        }
        
        var internalLogger = logger ?? NullLogger.Instance;
        
        if (internalLogger.IsEnabled(LogLevel.Debug))
            internalLogger.LogDebug("Computing EC-MQV full shared secret on curve {Curve}", localStatic.CurveName);
        
        try
        {
            // Create MQV parameters
            var mqvPrivate = new MqvPrivateParameters(
                localStatic.PrivateKey.ToBouncyCastleParameters(),
                localEphemeral.PrivateKey.ToBouncyCastleParameters());
                
            var mqvPublic = new MqvPublicParameters(
                remoteStatic.ToBouncyCastleParameters(),
                remoteEphemeral.ToBouncyCastleParameters());
            
            // Perform agreement
            var agreement = new ECMqvBasicAgreement();
            agreement.Init(mqvPrivate);
            
            var z = agreement.CalculateAgreement(mqvPublic);
            var sharedSecret = FormatSharedSecret(z, localStatic.PrivateKey.Parameters.Curve.FieldSize);
            
            if (internalLogger.IsEnabled(LogLevel.Debug))
                internalLogger.LogDebug("Successfully computed EC-MQV shared secret of {Length} bytes", sharedSecret.Length);
            
            return sharedSecret;
        }
        catch (Exception ex) when (ex is not CryptographicException)
        {
            internalLogger.LogError(ex, "Failed to compute EC-MQV shared secret");
            throw new KeyAgreementException("Failed to compute MQV shared secret", ex);
        }
    }
    
    /// <summary>
    /// Computes EC-MQV one-pass shared secret.
    /// In one-pass MQV, the initiator uses their static key as both static and ephemeral.
    /// </summary>
    /// <param name="localStatic">The local static key pair (used as both static and ephemeral).</param>
    /// <param name="remoteStatic">The remote party's static public key.</param>
    /// <param name="remoteEphemeral">The remote party's ephemeral public key.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <returns>The computed shared secret.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="KeyAgreementException">Thrown when curves don't match or agreement fails.</exception>
    public static SharedSecret ComputeOnePassMqv(
        EcKeyPair localStatic,
        EcPublicKey remoteStatic,
        EcPublicKey remoteEphemeral,
        ILogger? logger = null)
    {
        if (localStatic == null) throw new ArgumentNullException(nameof(localStatic));
        if (remoteStatic == null) throw new ArgumentNullException(nameof(remoteStatic));
        if (remoteEphemeral == null) throw new ArgumentNullException(nameof(remoteEphemeral));
        
        var internalLogger = logger ?? NullLogger.Instance;
        
        if (internalLogger.IsEnabled(LogLevel.Debug))
            internalLogger.LogDebug("Computing EC-MQV one-pass shared secret on curve {Curve}", localStatic.CurveName);
        
        // In one-pass MQV, the initiator uses their static key as both static and ephemeral
        return ComputeFullMqv(localStatic, localStatic, remoteStatic, remoteEphemeral, logger);
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