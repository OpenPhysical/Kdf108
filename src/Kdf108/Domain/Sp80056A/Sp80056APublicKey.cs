// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;

namespace Kdf108.Domain.Sp80056A;

/// <summary>
/// Represents an EC public key as defined in NIST SP 800-56A.
/// Encapsulates the public key point and its associated curve parameters.
/// </summary>
public class Sp80056APublicKey
{
    /// <summary>
    /// Gets the elliptic curve point representing the public key.
    /// </summary>
    public ECPoint PublicPoint { get; }

    /// <summary>
    /// Gets the elliptic curve domain parameters.
    /// </summary>
    public ECDomainParameters DomainParameters { get; }

    /// <summary>
    /// Gets the name of the curve (e.g., "P-256", "P-384", "P-521").
    /// </summary>
    public string CurveName { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056APublicKey"/> class.
    /// </summary>
    /// <param name="publicPoint">The EC point representing the public key.</param>
    /// <param name="domainParameters">The elliptic curve domain parameters.</param>
    /// <param name="curveName">The name of the curve.</param>
    public Sp80056APublicKey(ECPoint publicPoint, ECDomainParameters domainParameters, string curveName)
    {
        PublicPoint = publicPoint ?? throw new ArgumentNullException(nameof(publicPoint));
        DomainParameters = domainParameters ?? throw new ArgumentNullException(nameof(domainParameters));
        CurveName = curveName ?? throw new ArgumentNullException(nameof(curveName));
    }

    /// <summary>
    /// Creates a public key from BouncyCastle EC public key parameters.
    /// </summary>
    /// <param name="publicKeyParameters">The EC public key parameters.</param>
    /// <param name="curveName">The name of the curve.</param>
    /// <returns>A new instance of <see cref="Sp80056APublicKey"/>.</returns>
    public static Sp80056APublicKey FromBouncyCastleParameters(ECPublicKeyParameters publicKeyParameters, string curveName)
    {
        if (publicKeyParameters == null) throw new ArgumentNullException(nameof(publicKeyParameters));
        
        return new Sp80056APublicKey(
            publicKeyParameters.Q,
            publicKeyParameters.Parameters,
            curveName);
    }

    /// <summary>
    /// Creates a public key from a byte array representation.
    /// </summary>
    /// <param name="encoded">The encoded public key bytes (compressed or uncompressed format).</param>
    /// <param name="domainParameters">The elliptic curve domain parameters.</param>
    /// <param name="curveName">The name of the curve.</param>
    /// <returns>A new instance of <see cref="Sp80056APublicKey"/>.</returns>
    public static Sp80056APublicKey FromBytes(byte[] encoded, ECDomainParameters domainParameters, string curveName)
    {
        if (encoded == null) throw new ArgumentNullException(nameof(encoded));
        if (domainParameters == null) throw new ArgumentNullException(nameof(domainParameters));

        var point = domainParameters.Curve.DecodePoint(encoded);
        return new Sp80056APublicKey(point, domainParameters, curveName);
    }

    /// <summary>
    /// Converts the public key to its byte array representation.
    /// </summary>
    /// <param name="compressed">Whether to use compressed format. Default is false (uncompressed).</param>
    /// <returns>The encoded public key bytes.</returns>
    public byte[] ToBytes(bool compressed = false)
    {
        return PublicPoint.GetEncoded(compressed);
    }

    /// <summary>
    /// Converts the public key to BouncyCastle EC public key parameters.
    /// </summary>
    /// <returns>The EC public key parameters.</returns>
    public ECPublicKeyParameters ToBouncyCastleParameters()
    {
        return new ECPublicKeyParameters(PublicPoint, DomainParameters);
    }

    /// <summary>
    /// Validates that the public key is valid according to SP 800-56A requirements.
    /// </summary>
    /// <returns>True if the public key is valid, false otherwise.</returns>
    public bool IsValid()
    {
        // Check if point is at infinity
        if (PublicPoint.IsInfinity)
            return false;

        // Check if point is on the curve
        if (!PublicPoint.IsValid())
            return false;

        // Check if point has correct order
        var nQ = PublicPoint.Multiply(DomainParameters.N);
        if (!nQ.IsInfinity)
            return false;

        return true;
    }

    /// <summary>
    /// Determines whether the specified object is equal to the current public key.
    /// </summary>
    /// <param name="obj">The object to compare with the current public key.</param>
    /// <returns>True if the specified object is equal to the current public key; otherwise, false.</returns>
    public override bool Equals(object? obj)
    {
        if (obj is not Sp80056APublicKey other)
            return false;

        return PublicPoint.Equals(other.PublicPoint) && 
               DomainParameters.Equals(other.DomainParameters) &&
               CurveName.Equals(other.CurveName);
    }

    /// <summary>
    /// Serves as the default hash function.
    /// </summary>
    /// <returns>A hash code for the current public key.</returns>
    public override int GetHashCode()
    {
        return HashCode.Combine(PublicPoint, DomainParameters, CurveName);
    }
}
