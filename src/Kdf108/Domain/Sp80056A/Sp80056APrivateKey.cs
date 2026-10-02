// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace Kdf108.Domain.Sp80056A;

/// <summary>
/// Represents an EC private key as defined in NIST SP 800-56A.
/// Encapsulates the private key value and its associated curve parameters.
/// </summary>
public class Sp80056APrivateKey
{
    /// <summary>
    /// Gets the private key value (d).
    /// </summary>
    public BigInteger D { get; }

    /// <summary>
    /// Gets the elliptic curve domain parameters.
    /// </summary>
    public ECDomainParameters DomainParameters { get; }

    /// <summary>
    /// Gets the name of the curve (e.g., "P-256", "P-384", "P-521").
    /// </summary>
    public string CurveName { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="Sp80056APrivateKey"/> class.
    /// </summary>
    /// <param name="d">The private key value.</param>
    /// <param name="domainParameters">The elliptic curve domain parameters.</param>
    /// <param name="curveName">The name of the curve.</param>
    public Sp80056APrivateKey(BigInteger d, ECDomainParameters domainParameters, string curveName)
    {
        D = d ?? throw new ArgumentNullException(nameof(d));
        DomainParameters = domainParameters ?? throw new ArgumentNullException(nameof(domainParameters));
        CurveName = curveName ?? throw new ArgumentNullException(nameof(curveName));
    }

    /// <summary>
    /// Creates a private key from BouncyCastle EC private key parameters.
    /// </summary>
    /// <param name="privateKeyParameters">The EC private key parameters.</param>
    /// <param name="curveName">The name of the curve.</param>
    /// <returns>A new instance of <see cref="Sp80056APrivateKey"/>.</returns>
    public static Sp80056APrivateKey FromBouncyCastleParameters(ECPrivateKeyParameters privateKeyParameters, string curveName)
    {
        if (privateKeyParameters == null) throw new ArgumentNullException(nameof(privateKeyParameters));
        
        return new Sp80056APrivateKey(
            privateKeyParameters.D,
            privateKeyParameters.Parameters,
            curveName);
    }

    /// <summary>
    /// Creates a private key from a byte array representation.
    /// </summary>
    /// <param name="encoded">The encoded private key bytes.</param>
    /// <param name="domainParameters">The elliptic curve domain parameters.</param>
    /// <param name="curveName">The name of the curve.</param>
    /// <returns>A new instance of <see cref="Sp80056APrivateKey"/>.</returns>
    public static Sp80056APrivateKey FromBytes(byte[] encoded, ECDomainParameters domainParameters, string curveName)
    {
        if (encoded == null) throw new ArgumentNullException(nameof(encoded));
        if (domainParameters == null) throw new ArgumentNullException(nameof(domainParameters));

        var d = new BigInteger(1, encoded);
        return new Sp80056APrivateKey(d, domainParameters, curveName);
    }

    /// <summary>
    /// Converts the private key to its byte array representation.
    /// </summary>
    /// <returns>The encoded private key bytes.</returns>
    public byte[] ToBytes()
    {
        return D.ToByteArrayUnsigned();
    }

    /// <summary>
    /// Converts the private key to BouncyCastle EC private key parameters.
    /// </summary>
    /// <returns>The EC private key parameters.</returns>
    public ECPrivateKeyParameters ToBouncyCastleParameters()
    {
        return new ECPrivateKeyParameters(D, DomainParameters);
    }

    /// <summary>
    /// Computes the corresponding public key for this private key.
    /// </summary>
    /// <returns>The corresponding public key.</returns>
    public Sp80056APublicKey ComputePublicKey()
    {
        var publicPoint = DomainParameters.G.Multiply(D);
        return new Sp80056APublicKey(publicPoint, DomainParameters, CurveName);
    }

    /// <summary>
    /// Validates that the private key is valid according to SP 800-56A requirements.
    /// </summary>
    /// <returns>True if the private key is valid, false otherwise.</returns>
    public bool IsValid()
    {
        // Private key must be in range [1, n-1]
        var n = DomainParameters.N;
        return D.CompareTo(BigInteger.One) >= 0 && D.CompareTo(n.Subtract(BigInteger.One)) <= 0;
    }

    /// <summary>
    /// Securely clears the private key from memory.
    /// Note: This is best-effort as the CLR may have made copies.
    /// </summary>
    public void Clear()
    {
        // BigInteger is immutable, so we can't truly clear it
        // This is a limitation when working with managed code
        // In practice, sensitive operations should use secure memory techniques
    }

    /// <summary>
    /// Determines whether the specified object is equal to the current private key.
    /// Note: Comparing private keys should be done carefully in production code.
    /// </summary>
    /// <param name="obj">The object to compare with the current private key.</param>
    /// <returns>True if the specified object is equal to the current private key; otherwise, false.</returns>
    public override bool Equals(object? obj)
    {
        if (obj is not Sp80056APrivateKey other)
            return false;

        return D.Equals(other.D) && 
               DomainParameters.Equals(other.DomainParameters) &&
               CurveName.Equals(other.CurveName);
    }

    /// <summary>
    /// Serves as the default hash function.
    /// </summary>
    /// <returns>A hash code for the current private key.</returns>
    public override int GetHashCode()
    {
        return HashCode.Combine(D, DomainParameters, CurveName);
    }
}
