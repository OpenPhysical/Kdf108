// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Exceptions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Kdf108.Domain.Sp80056A;

/// <summary>
/// Represents an immutable elliptic curve public key for use in ECDH key agreement.
/// This class validates the key at construction time and guarantees the key
/// is always in a valid state.
/// </summary>
/// <example>
/// <code>
/// // Create a public key from bytes
/// var publicKey = new EcPublicKey(keyBytes, "P-256");
/// 
/// // Use in key agreement
/// var sharedSecret = EcdhKeyAgreement.ComputeSharedSecret(myPrivateKey, publicKey);
/// </code>
/// </example>
public sealed class EcPublicKey : IEquatable<EcPublicKey>
{
    private readonly ECPoint _q;
    private readonly ECDomainParameters _parameters;
    private readonly string _curveName;
    private readonly ILogger<EcPublicKey> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="EcPublicKey"/> class.
    /// </summary>
    /// <param name="keyData">The public key bytes in uncompressed format.</param>
    /// <param name="curveName">The name of the elliptic curve (e.g., "P-256", "P-384").</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <exception cref="ArgumentNullException">Thrown when keyData or curveName is null.</exception>
    /// <exception cref="UnsupportedCurveException">Thrown when the curve is not supported.</exception>
    /// <exception cref="InvalidPublicKeyException">Thrown when the key data is invalid.</exception>
    public EcPublicKey(byte[] keyData, string curveName, ILogger<EcPublicKey>? logger = null)
    {
        if (keyData == null) throw new ArgumentNullException(nameof(keyData));
        if (string.IsNullOrEmpty(curveName)) throw new ArgumentNullException(nameof(curveName));
        
        _logger = logger ?? NullLogger<EcPublicKey>.Instance;
        
        if (_logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Creating EC public key for curve {CurveName}", curveName);
        
        // Get curve parameters
        _parameters = CurveRegistry.GetParameters(curveName)
            ?? throw new UnsupportedCurveException($"Curve '{curveName}' is not supported");
        _curveName = curveName;
        
        // Validate format and length
        ValidateKeyFormat(keyData);
        
        // Parse the point
        try
        {
            _q = _parameters.Curve.DecodePoint(keyData);
        }
        catch (ArgumentException ex)
        {
            _logger.LogError(ex, "Failed to decode public key point for curve {CurveName}", curveName);
            throw new PublicKeyDecodingException("Failed to decode public key point", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error decoding public key for curve {CurveName}", curveName);
            throw new PublicKeyDecodingException("Unexpected error decoding public key", ex);
        }
        
        // Validate the point
        ValidatePoint();
        
        if (_logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Successfully created EC public key for curve {CurveName}", curveName);
    }

    /// <summary>
    /// Creates a public key from BouncyCastle EC public key parameters.
    /// </summary>
    /// <param name="bcPublicKey">The BouncyCastle public key parameters.</param>
    /// <param name="curveName">The name of the curve.</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <returns>A new instance of <see cref="EcPublicKey"/>.</returns>
    public static EcPublicKey FromBouncyCastle(ECPublicKeyParameters bcPublicKey, string curveName, ILogger<EcPublicKey>? logger = null)
    {
        if (bcPublicKey == null) throw new ArgumentNullException(nameof(bcPublicKey));
        
        // Extract bytes and use standard constructor
        return new EcPublicKey(bcPublicKey.Q.GetEncoded(false), curveName, logger);
    }

    /// <summary>
    /// Converts the public key to BouncyCastle EC public key parameters.
    /// </summary>
    /// <returns>The EC public key parameters.</returns>
    internal ECPublicKeyParameters ToBouncyCastleParameters()
    {
        return new ECPublicKeyParameters(_q, _parameters);
    }

    /// <summary>
    /// Gets the public key as a byte array.
    /// </summary>
    /// <param name="compressed">Whether to use compressed format. Default is false (uncompressed).</param>
    /// <returns>The public key bytes.</returns>
    public byte[] ToByteArray(bool compressed = false)
    {
        return _q.GetEncoded(compressed);
    }

    /// <summary>
    /// Gets the elliptic curve point representing the public key.
    /// </summary>
    internal ECPoint Q => _q;

    /// <summary>
    /// Gets the elliptic curve domain parameters.
    /// </summary>
    internal ECDomainParameters Parameters => _parameters;

    /// <summary>
    /// Gets the name of the curve.
    /// </summary>
    public string CurveName => _curveName;

    private void ValidateKeyFormat(byte[] keyData)
    {
        // Validate format
        if (keyData.Length == 0)
        {
            throw new PublicKeyInvalidLengthException("Public key cannot be empty");
        }
        
        if (keyData[0] != 0x04)
        {
            throw new PublicKeyInvalidFormatException(
                $"Only uncompressed public keys are supported. Expected format byte 0x04, got 0x{keyData[0]:X2}");
        }
        
        // Validate length
        var expectedCoordLength = (_parameters.Curve.FieldSize + 7) / 8;
        var expectedKeyLength = 1 + 2 * expectedCoordLength; // 1 byte for 0x04 prefix + 2 coordinates
        
        if (keyData.Length != expectedKeyLength)
        {
            _logger.LogError("Public key has incorrect length for curve {CurveName}. Expected {Expected} bytes, got {Actual} bytes",
                _curveName, expectedKeyLength, keyData.Length);
            throw new PublicKeyInvalidLengthException(
                $"Invalid public key length for curve {_curveName}. Expected {expectedKeyLength} bytes, got {keyData.Length} bytes");
        }
    }

    private void ValidatePoint()
    {
        // Point at infinity check
        if (_q.IsInfinity)
        {
            _logger.LogError("Public key validation failed: point at infinity");
            throw new PublicKeyAtInfinityException("Public key point cannot be at infinity");
        }
        
        // On-curve check (this is what BouncyCastle's IsValid does internally)
        if (!_q.IsValid())
        {
            _logger.LogError("Public key validation failed: point not on curve {CurveName}", _curveName);
            throw new PublicKeyNotOnCurveException($"Public key point is not on curve {_curveName}");
        }
        
        // Validate coordinates are not null and not zero
        var x = _q.AffineXCoord?.ToBigInteger();
        var y = _q.AffineYCoord?.ToBigInteger();
        
        if (x == null || y == null)
        {
            _logger.LogError("Public key validation failed: null coordinates");
            throw new PublicKeyDecodingException("Public key has null coordinates", new ArgumentNullException());
        }
        
        if (x.SignValue == 0)
        {
            _logger.LogError("Public key validation failed: X coordinate is zero");
            throw new InvalidPublicKeyXCoordinateException("Public key X coordinate cannot be zero");
        }
        
        if (y.SignValue == 0)
        {
            _logger.LogError("Public key validation failed: Y coordinate is zero");
            throw new InvalidPublicKeyYCoordinateException("Public key Y coordinate cannot be zero");
        }
        
        // For prime curves, additional coordinate range validation
        if (_parameters.Curve is Org.BouncyCastle.Math.EC.FpCurve fpCurve)
        {
            var p = fpCurve.Q;
            
            if (x.SignValue < 0 || x.CompareTo(p) >= 0)
            {
                _logger.LogError("Public key validation failed: X coordinate out of range [0, p-1]");
                throw new InvalidPublicKeyXCoordinateException(
                    $"Public key X coordinate must be in range [0, p-1] for curve {_curveName}");
            }
            
            if (y.SignValue < 0 || y.CompareTo(p) >= 0)
            {
                _logger.LogError("Public key validation failed: Y coordinate out of range [0, p-1]");
                throw new InvalidPublicKeyYCoordinateException(
                    $"Public key Y coordinate must be in range [0, p-1] for curve {_curveName}");
            }
        }
        
        // Order check - point must have correct order
        var nQ = _q.Multiply(_parameters.N);
        if (!nQ.IsInfinity)
        {
            _logger.LogError("Public key validation failed: point does not have correct order");
            throw new PublicKeyIncorrectOrderException($"Public key point does not have correct order for curve {_curveName}");
        }
        
        // Cofactor check for curves where h > 1
        if (_parameters.H != null && !_parameters.H.Equals(BigInteger.One))
        {
            var hQ = _q.Multiply(_parameters.H);
            if (hQ.IsInfinity)
            {
                _logger.LogError("Public key validation failed: point is in small subgroup");
                throw new PublicKeySmallSubgroupException(
                    $"Public key is in a small subgroup for curve {_curveName}");
            }
        }
        
        if (_logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("Public key validation passed for curve {CurveName}", _curveName);
    }

    /// <summary>
    /// Determines whether the specified <see cref="EcPublicKey"/> is equal to the current key.
    /// </summary>
    /// <param name="other">The key to compare with the current key.</param>
    /// <returns>true if the specified key is equal to the current key; otherwise, false.</returns>
    public bool Equals(EcPublicKey? other)
    {
        if (other is null) return false;
        if (ReferenceEquals(this, other)) return true;
        
        return _q.Equals(other._q) && _curveName.Equals(other._curveName, StringComparison.Ordinal);
    }

    /// <summary>
    /// Determines whether the specified object is equal to the current key.
    /// </summary>
    /// <param name="obj">The object to compare with the current key.</param>
    /// <returns>true if the specified object is equal to the current key; otherwise, false.</returns>
    public override bool Equals(object? obj) => Equals(obj as EcPublicKey);

    /// <summary>
    /// Serves as the default hash function.
    /// </summary>
    /// <returns>A hash code for the current key.</returns>
    public override int GetHashCode() => HashCode.Combine(_q, _curveName);

    /// <summary>
    /// Returns a string representation of this public key.
    /// </summary>
    /// <returns>A string representation of this key.</returns>
    public override string ToString() => $"EcPublicKey[{_curveName}]";
}