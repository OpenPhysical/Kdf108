// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Kdf108.Domain.Sp80056A;

/// <summary>
/// Represents an immutable elliptic curve key pair (private and public key).
/// This class validates that the keys correspond to each other at construction time.
/// </summary>
/// <example>
/// <code>
/// // Create from existing keys
/// var keyPair = EcKeyPair.Create(privateKey, publicKey);
/// 
/// // Generate from private key only
/// var keyPair = EcKeyPair.GenerateFrom(privateKey);
/// 
/// // Generate new random keypair
/// var keyPair = EcKeyPair.GenerateRandom("P-256");
/// </code>
/// </example>
public sealed class EcKeyPair : IEquatable<EcKeyPair>
{
    private readonly EcPrivateKey _privateKey;
    private readonly EcPublicKey _publicKey;
    private readonly ILogger<EcKeyPair> _logger;

    // Private constructor - use factory methods
    private EcKeyPair(EcPrivateKey privateKey, EcPublicKey publicKey, ILogger<EcKeyPair>? logger = null)
    {
        _privateKey = privateKey;
        _publicKey = publicKey;
        _logger = logger ?? NullLogger<EcKeyPair>.Instance;
    }

    /// <summary>
    /// Creates a keypair from separate private and public keys.
    /// This validates that the keys correspond to each other.
    /// If they don't match, throws KeyMismatchException immediately.
    /// </summary>
    /// <param name="privateKey">The private key.</param>
    /// <param name="publicKey">The public key.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <returns>A validated key pair.</returns>
    /// <exception cref="ArgumentNullException">Thrown when either key is null.</exception>
    /// <exception cref="KeyMismatchException">Thrown when the keys don't form a valid pair.</exception>
    public static EcKeyPair Create(EcPrivateKey privateKey, EcPublicKey publicKey, ILogger<EcKeyPair>? logger = null)
    {
        if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
        if (publicKey == null) throw new ArgumentNullException(nameof(publicKey));
        
        var internalLogger = logger ?? NullLogger<EcKeyPair>.Instance;
        
        if (internalLogger.IsEnabled(LogLevel.Debug))
            internalLogger.LogDebug("Creating EC key pair for curve {CurveName}", privateKey.CurveName);
        
        // Keys must be for same curve
        if (!privateKey.CurveName.Equals(publicKey.CurveName, StringComparison.Ordinal))
        {
            internalLogger.LogError("Key curve mismatch: private key is for curve {PrivateCurve} but public key is for curve {PublicCurve}",
                privateKey.CurveName, publicKey.CurveName);
            throw KeyMismatchException.Create(privateKey.CurveName, publicKey.CurveName);
        }
        
        // Compute what the public key SHOULD be
        var expectedPublicKey = privateKey.ComputePublicKey();
        
        // They must match exactly
        if (!expectedPublicKey.Equals(publicKey))
        {
            internalLogger.LogError("Public key does not correspond to private key for curve {CurveName}", privateKey.CurveName);
            throw KeyMismatchException.CreateForKeyPair();
        }
        
        if (internalLogger.IsEnabled(LogLevel.Debug))
            internalLogger.LogDebug("Successfully validated EC key pair for curve {CurveName}", privateKey.CurveName);
        
        // If we get here, we have a VALID keypair
        return new EcKeyPair(privateKey, publicKey, logger);
    }

    /// <summary>
    /// Creates a keypair from raw bytes.
    /// This is a convenience method that constructs both keys and validates them.
    /// </summary>
    /// <param name="privateKeyBytes">The private key bytes.</param>
    /// <param name="publicKeyBytes">The public key bytes.</param>
    /// <param name="curveName">The name of the curve.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <returns>A validated key pair.</returns>
    public static EcKeyPair Create(byte[] privateKeyBytes, byte[] publicKeyBytes, string curveName, ILogger<EcKeyPair>? logger = null)
    {
        var privateKey = new EcPrivateKey(privateKeyBytes, curveName);
        var publicKey = new EcPublicKey(publicKeyBytes, curveName);
        return Create(privateKey, publicKey, logger);
    }

    /// <summary>
    /// Generates a keypair from a private key by computing the corresponding public key.
    /// </summary>
    /// <param name="privateKey">The private key.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <returns>A key pair with the computed public key.</returns>
    /// <exception cref="ArgumentNullException">Thrown when privateKey is null.</exception>
    public static EcKeyPair GenerateFrom(EcPrivateKey privateKey, ILogger<EcKeyPair>? logger = null)
    {
        if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
        
        var internalLogger = logger ?? NullLogger<EcKeyPair>.Instance;
        
        if (internalLogger.IsEnabled(LogLevel.Debug))
            internalLogger.LogDebug("Generating EC key pair from private key for curve {CurveName}", privateKey.CurveName);
        
        var publicKey = privateKey.ComputePublicKey();
        return new EcKeyPair(privateKey, publicKey, logger);
    }

    /// <summary>
    /// Generates a new random keypair for the specified curve.
    /// </summary>
    /// <param name="curveName">The name of the curve.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <returns>A new random key pair.</returns>
    /// <exception cref="UnsupportedCurveException">Thrown when the curve is not supported.</exception>
    public static EcKeyPair GenerateRandom(string curveName, ILogger<EcKeyPair>? logger = null)
    {
        if (string.IsNullOrEmpty(curveName)) throw new ArgumentNullException(nameof(curveName));
        
        var internalLogger = logger ?? NullLogger<EcKeyPair>.Instance;
        
        if (internalLogger.IsEnabled(LogLevel.Debug))
            internalLogger.LogDebug("Generating random EC key pair for curve {CurveName}", curveName);
        
        var parameters = CurveRegistry.GetParameters(curveName)
            ?? throw new UnsupportedCurveException($"Curve '{curveName}' is not supported");
        
        // Use BouncyCastle's secure random generator
        var keyGen = new ECKeyPairGenerator();
        keyGen.Init(new ECKeyGenerationParameters(parameters, new SecureRandom()));
        
        var bcKeyPair = keyGen.GenerateKeyPair();
        var bcPrivate = (ECPrivateKeyParameters)bcKeyPair.Private;
        var bcPublic = (ECPublicKeyParameters)bcKeyPair.Public;
        
        var privateKey = new EcPrivateKey(bcPrivate.D.ToByteArrayUnsigned(), curveName);
        var publicKey = new EcPublicKey(bcPublic.Q.GetEncoded(false), curveName);
        
        return new EcKeyPair(privateKey, publicKey, logger);
    }

    /// <summary>
    /// Gets the private key.
    /// </summary>
    public EcPrivateKey PrivateKey => _privateKey;

    /// <summary>
    /// Gets the public key.
    /// </summary>
    public EcPublicKey PublicKey => _publicKey;

    /// <summary>
    /// Gets the name of the curve.
    /// </summary>
    public string CurveName => _privateKey.CurveName;

    /// <summary>
    /// Determines whether the specified <see cref="EcKeyPair"/> is equal to the current key pair.
    /// </summary>
    /// <param name="other">The key pair to compare with the current key pair.</param>
    /// <returns>true if the specified key pair is equal to the current key pair; otherwise, false.</returns>
    public bool Equals(EcKeyPair? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        
        return _privateKey.Equals(other._privateKey) && _publicKey.Equals(other._publicKey);
    }

    /// <summary>
    /// Determines whether the specified object is equal to the current key pair.
    /// </summary>
    /// <param name="obj">The object to compare with the current key pair.</param>
    /// <returns>true if the specified object is equal to the current key pair; otherwise, false.</returns>
    public override bool Equals(object? obj) => Equals(obj as EcKeyPair);

    /// <summary>
    /// Serves as the default hash function.
    /// </summary>
    /// <returns>A hash code for the current key pair.</returns>
    public override int GetHashCode() => HashCode.Combine(_privateKey, _publicKey);

    /// <summary>
    /// Returns a string representation of this key pair.
    /// </summary>
    /// <returns>A string representation of this key pair.</returns>
    public override string ToString() => $"EcKeyPair[{CurveName}]";
}