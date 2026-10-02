// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Kdf108.Domain.Sp80056A;

/// <summary>
/// Represents an immutable elliptic curve private key for use in ECDH key agreement.
/// This class validates the key at construction time and guarantees the key
/// is always in a valid state.
/// </summary>
/// <example>
/// <code>
/// // Create a private key from bytes
/// var privateKey = new EcPrivateKey(keyBytes, "P-256");
/// 
/// // Generate corresponding public key
/// var publicKey = privateKey.ComputePublicKey();
/// 
/// // Create a validated key pair
/// var keyPair = EcKeyPair.GenerateFrom(privateKey);
/// </code>
/// </example>
public sealed class EcPrivateKey : IEquatable<EcPrivateKey>
{
    private readonly BigInteger _d;
    private readonly ECDomainParameters _parameters;
    private readonly string _curveName;
    private readonly ILogger<EcPrivateKey> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="EcPrivateKey"/> class.
    /// </summary>
    /// <param name="keyData">The private key bytes.</param>
    /// <param name="curveName">The name of the elliptic curve (e.g., "P-256", "P-384").</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <exception cref="ArgumentNullException">Thrown when keyData or curveName is null.</exception>
    /// <exception cref="UnsupportedCurveException">Thrown when the curve is not supported.</exception>
    /// <exception cref="InvalidPrivateKeyException">Thrown when the key data is invalid.</exception>
    public EcPrivateKey(byte[] keyData, string curveName, ILogger<EcPrivateKey>? logger = null)
    {
        if (keyData == null) throw new ArgumentNullException(nameof(keyData));
        if (string.IsNullOrEmpty(curveName)) throw new ArgumentNullException(nameof(curveName));
        
        _logger = logger ?? NullLogger<EcPrivateKey>.Instance;
        
        if (_logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Creating EC private key for curve {CurveName}", curveName);
        
        // Get curve parameters
        _parameters = CurveRegistry.GetParameters(curveName)
            ?? throw new UnsupportedCurveException($"Curve '{curveName}' is not supported");
        _curveName = curveName;
        
        // Parse key data
        _d = new BigInteger(1, keyData);
        
        // Validate immediately - fail fast!
        ValidateKey();
        
        if (_logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Successfully created EC private key for curve {CurveName}", curveName);
    }

    /// <summary>
    /// Creates a private key from BouncyCastle EC private key parameters.
    /// </summary>
    /// <param name="bcPrivateKey">The BouncyCastle private key parameters.</param>
    /// <param name="curveName">The name of the curve.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <returns>A new instance of <see cref="EcPrivateKey"/>.</returns>
    public static EcPrivateKey FromBouncyCastle(ECPrivateKeyParameters bcPrivateKey, string curveName, ILogger<EcPrivateKey>? logger = null)
    {
        if (bcPrivateKey == null) throw new ArgumentNullException(nameof(bcPrivateKey));
        
        // Extract bytes and use standard constructor
        return new EcPrivateKey(bcPrivateKey.D.ToByteArrayUnsigned(), curveName, logger);
    }

    /// <summary>
    /// Computes the corresponding public key for this private key.
    /// </summary>
    /// <param name="logger">Optional logger for the public key.</param>
    /// <returns>The corresponding public key.</returns>
    public EcPublicKey ComputePublicKey(ILogger<EcPublicKey>? logger = null)
    {
        if (_logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Computing public key from private key on curve {CurveName}", _curveName);
            
        var publicPoint = _parameters.G.Multiply(_d).Normalize();
        return new EcPublicKey(publicPoint.GetEncoded(false), _curveName, logger);
    }

    /// <summary>
    /// Converts the private key to BouncyCastle EC private key parameters.
    /// </summary>
    /// <returns>The EC private key parameters.</returns>
    internal ECPrivateKeyParameters ToBouncyCastleParameters()
    {
        return new ECPrivateKeyParameters(_d, _parameters);
    }

    /// <summary>
    /// Gets the private key value as a byte array.
    /// </summary>
    /// <returns>The private key bytes.</returns>
    public byte[] ToByteArray()
    {
        return _d.ToByteArrayUnsigned();
    }

    /// <summary>
    /// Gets the private key value (d).
    /// </summary>
    internal BigInteger D => _d;

    /// <summary>
    /// Gets the elliptic curve domain parameters.
    /// </summary>
    internal ECDomainParameters Parameters => _parameters;

    /// <summary>
    /// Gets the name of the curve.
    /// </summary>
    public string CurveName => _curveName;

    private void ValidateKey()
    {
        // Check if private key is zero
        if (_d.SignValue == 0)
        {
            _logger.LogError("Private key validation failed: key is zero");
            throw new PrivateKeyZeroException("Private key cannot be zero");
        }
        
        // Check if private key is negative
        if (_d.SignValue < 0)
        {
            _logger.LogError("Private key validation failed: key is negative");
            throw new PrivateKeyNegativeException("Private key must be positive");
        }
        
        // Check if private key is too large (must be < n)
        if (_d.CompareTo(_parameters.N) >= 0)
        {
            _logger.LogError("Private key validation failed: key >= curve order for curve {CurveName}", _curveName);
            throw new PrivateKeyTooLargeException($"Private key is out of range for curve {_curveName} - must be less than curve order");
        }
        
        if (_logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("Private key validation passed for curve {CurveName}", _curveName);
    }

    /// <summary>
    /// Determines whether the specified <see cref="EcPrivateKey"/> is equal to the current key.
    /// </summary>
    /// <param name="other">The key to compare with the current key.</param>
    /// <returns>true if the specified key is equal to the current key; otherwise, false.</returns>
    public bool Equals(EcPrivateKey? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        
        return _d.Equals(other._d) && _curveName.Equals(other._curveName, StringComparison.Ordinal);
    }

    /// <summary>
    /// Determines whether the specified object is equal to the current key.
    /// </summary>
    /// <param name="obj">The object to compare with the current key.</param>
    /// <returns>true if the specified object is equal to the current key; otherwise, false.</returns>
    public override bool Equals(object? obj) => Equals(obj as EcPrivateKey);

    /// <summary>
    /// Serves as the default hash function.
    /// </summary>
    /// <returns>A hash code for the current key.</returns>
    public override int GetHashCode() => HashCode.Combine(_d, _curveName);

    /// <summary>
    /// Returns a string representation of this private key.
    /// Note: Does not expose the actual key value for security.
    /// </summary>
    /// <returns>A string representation of this key.</returns>
    public override string ToString() => $"EcPrivateKey[{_curveName}]";
}