// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#if DEBUG

using System;
using System.Text;
using Kdf108.Domain.Sp80056A;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace Kdf108.Debug;

/// <summary>
/// Debug utilities for SP 800-56A ECDH operations.
/// Only available in DEBUG builds.
/// </summary>
public static class Sp80056ADebug
{
    /// <summary>
    /// Gets detailed information about an ECDH operation's intermediate values.
    /// </summary>
    /// <param name="privateKey">The private key used.</param>
    /// <param name="publicKey">The public key used.</param>
    /// <param name="sharedSecret">The resulting shared secret.</param>
    /// <returns>A string containing detailed intermediate values.</returns>
    public static string GetEcdhIntermediates(
        Sp80056APrivateKey privateKey,
        Sp80056APublicKey publicKey,
        byte[] sharedSecret)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== SP 800-56A ECDH Debug Information ===");
        sb.AppendLine($"Timestamp: {DateTime.UtcNow:O}");
        sb.AppendLine();

        sb.AppendLine($"Curve: {privateKey.CurveName}");
        sb.AppendLine();

        sb.AppendLine("Private Key:");
        sb.AppendLine($"  d (hex): {privateKey.D.ToString(16)}");
        sb.AppendLine($"  d (bit length): {privateKey.D.BitLength}");
        sb.AppendLine();

        sb.AppendLine("Public Key:");
        sb.AppendLine($"  Q.X (hex): {publicKey.PublicPoint.XCoord.ToBigInteger().ToString(16)}");
        sb.AppendLine($"  Q.Y (hex): {publicKey.PublicPoint.YCoord.ToBigInteger().ToString(16)}");
        sb.AppendLine($"  On curve: {publicKey.PublicPoint.IsValid()}");
        sb.AppendLine($"  At infinity: {publicKey.PublicPoint.IsInfinity}");
        sb.AppendLine();

        // Compute shared point for debugging
        var sharedPoint = publicKey.PublicPoint.Multiply(privateKey.D);
        sb.AppendLine("Shared Point (d * Q):");
        sb.AppendLine($"  X (hex): {sharedPoint.XCoord.ToBigInteger().ToString(16)}");
        sb.AppendLine($"  Y (hex): {sharedPoint.YCoord.ToBigInteger().ToString(16)}");
        sb.AppendLine();

        sb.AppendLine("Shared Secret:");
        sb.AppendLine($"  Length: {sharedSecret.Length} bytes");
        sb.AppendLine($"  Value (hex): {Convert.ToHexString(sharedSecret)}");

        return sb.ToString();
    }

    /// <summary>
    /// Validates an EC point and provides detailed diagnostic information.
    /// </summary>
    /// <param name="point">The EC point to validate.</param>
    /// <param name="domainParameters">The domain parameters.</param>
    /// <param name="logger">Optional logger for output.</param>
    /// <returns>A detailed validation report.</returns>
    public static string ValidateEcPoint(
        ECPoint point,
        ECDomainParameters domainParameters,
        ILogger? logger = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== EC Point Validation ===");

        // Check if at infinity
        if (point.IsInfinity)
        {
            sb.AppendLine("❌ Point is at infinity");
            logger?.LogWarning("EC point validation failed: point at infinity");
            return sb.ToString();
        }
        sb.AppendLine("✓ Point is not at infinity");

        // Check if on curve
        if (!point.IsValid())
        {
            sb.AppendLine("❌ Point is not on the curve");
            logger?.LogWarning("EC point validation failed: point not on curve");
            return sb.ToString();
        }
        sb.AppendLine("✓ Point is on the curve");

        // Check order
        var nP = point.Multiply(domainParameters.N);
        if (!nP.IsInfinity)
        {
            sb.AppendLine("❌ Point does not have correct order");
            logger?.LogWarning("EC point validation failed: incorrect order");
        }
        else
        {
            sb.AppendLine("✓ Point has correct order");
        }

        // Additional checks
        var x = point.XCoord.ToBigInteger();
        var y = point.YCoord.ToBigInteger();
        var p = domainParameters.Curve.Field.Characteristic;

        sb.AppendLine();
        sb.AppendLine("Point Coordinates:");
        sb.AppendLine($"  X: {x.ToString(16)}");
        sb.AppendLine($"  Y: {y.ToString(16)}");
        sb.AppendLine($"  X < p: {x.CompareTo(p) < 0}");
        sb.AppendLine($"  Y < p: {y.CompareTo(p) < 0}");

        logger?.LogDebug("EC point validation completed");
        return sb.ToString();
    }

    /// <summary>
    /// Generates a test key pair for debugging purposes.
    /// </summary>
    /// <param name="curveName">The curve name (P-256, P-384, P-521).</param>
    /// <param name="logger">Optional logger.</param>
    /// <returns>A tuple containing the private and public keys.</returns>
    public static (Sp80056APrivateKey privateKey, Sp80056APublicKey publicKey) GenerateTestKeyPair(
        string curveName,
        ILogger? logger = null)
    {
        logger?.LogDebug("Generating test key pair for curve: {CurveName}", curveName);

        ECDomainParameters domainParams;
        switch (curveName.ToUpperInvariant())
        {
            case "P-256":
                var p256 = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName("P-256");
                domainParams = new ECDomainParameters(p256.Curve, p256.G, p256.N, p256.H, p256.GetSeed());
                break;
            case "P-384":
                var p384 = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName("P-384");
                domainParams = new ECDomainParameters(p384.Curve, p384.G, p384.N, p384.H, p384.GetSeed());
                break;
            case "P-521":
                var p521 = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName("P-521");
                domainParams = new ECDomainParameters(p521.Curve, p521.G, p521.N, p521.H, p521.GetSeed());
                break;
            default:
                throw new ArgumentException($"Unsupported curve: {curveName}");
        }

        // Generate random private key
        var random = new Random();
        var privateKeyBytes = new byte[domainParams.N.BitLength / 8];
        random.NextBytes(privateKeyBytes);
        var d = new BigInteger(1, privateKeyBytes).Mod(domainParams.N.Subtract(BigInteger.One)).Add(BigInteger.One);

        var privateKey = new Sp80056APrivateKey(d, domainParams, curveName);
        var publicKey = privateKey.ComputePublicKey();

        logger?.LogDebug("Generated test key pair successfully");
        return (privateKey, publicKey);
    }

    /// <summary>
    /// Compares two shared secrets and reports differences.
    /// </summary>
    /// <param name="secret1">First shared secret.</param>
    /// <param name="secret2">Second shared secret.</param>
    /// <returns>Comparison report.</returns>
    public static string CompareSharedSecrets(byte[] secret1, byte[] secret2)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Shared Secret Comparison ===");
        
        sb.AppendLine($"Secret 1 length: {secret1.Length} bytes");
        sb.AppendLine($"Secret 2 length: {secret2.Length} bytes");
        
        if (secret1.Length != secret2.Length)
        {
            sb.AppendLine("❌ Lengths differ!");
            return sb.ToString();
        }

        bool equal = true;
        int firstDifference = -1;
        
        for (int i = 0; i < secret1.Length; i++)
        {
            if (secret1[i] != secret2[i])
            {
                equal = false;
                if (firstDifference == -1)
                    firstDifference = i;
            }
        }

        if (equal)
        {
            sb.AppendLine("✓ Shared secrets are identical");
        }
        else
        {
            sb.AppendLine($"❌ Shared secrets differ at byte {firstDifference}");
            sb.AppendLine($"Secret 1: {Convert.ToHexString(secret1)}");
            sb.AppendLine($"Secret 2: {Convert.ToHexString(secret2)}");
        }

        return sb.ToString();
    }
}


#endif