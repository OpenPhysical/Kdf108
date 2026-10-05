// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Kdf108.Domain.Sp80056C;

/// <summary>
/// Implements the HMAC-based Key Derivation Function (KDF) as specified in NIST SP 800-56C Rev 2.
/// This KDF uses HMAC with an approved hash function to derive key material from a shared secret.
/// </summary>
/// <remarks>
/// The HMAC-based KDF implements the following algorithm:
/// KDF(Z, OtherInfo) = HMAC(salt, 0x00000001 || Z || OtherInfo) || HMAC(salt, 0x00000002 || Z || OtherInfo) || ...
/// where the salt is derived from Z, and the counter is a 32-bit big-endian integer.
/// 
/// For SP 800-56C, when no salt is provided, the salt is set to all zeros with length equal to the hash output size.
/// </remarks>
public static class Sp80056CHmacKdf
{
    /// <summary>
    /// Derives key material using the SP 800-56C HMAC-based KDF.
    /// </summary>
    /// <param name="sharedSecret">The shared secret (Z) obtained from key agreement.</param>
    /// <param name="otherInfo">
    /// Additional information used in key derivation. This typically includes algorithm identifiers,
    /// key usage information, and other context-specific data.
    /// </param>
    /// <param name="outputLengthBytes">The desired length of the derived key material in bytes.</param>
    /// <param name="hmacAlgorithm">The Bouncy Castle HMAC implementation to use for the KDF.</param>
    /// <param name="salt">
    /// Optional salt value. If null, a zero-filled salt of appropriate length is used.
    /// </param>
    /// <returns>A byte array containing the derived key material of the specified length.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when any of the required parameters are null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when the output length is zero or negative.
    /// </exception>
    public static byte[] DeriveKeyMaterial(
        byte[] sharedSecret, 
        byte[] otherInfo, 
        int outputLengthBytes, 
        IMac hmacAlgorithm,
        byte[]? salt = null)
    {
        if (sharedSecret == null)
            throw new ArgumentNullException(nameof(sharedSecret));
        if (otherInfo == null)
            throw new ArgumentNullException(nameof(otherInfo));
        if (hmacAlgorithm == null)
            throw new ArgumentNullException(nameof(hmacAlgorithm));
        if (outputLengthBytes <= 0)
            throw new ArgumentException("Output length must be positive", nameof(outputLengthBytes));

        // If no salt provided, use zeros (as per SP 800-56C)
        if (salt == null)
        {
            salt = new byte[hmacAlgorithm.GetMacSize()];
        }

        hmacAlgorithm.Init(new KeyParameter(salt));

        var hmacLengthBytes = hmacAlgorithm.GetMacSize();
        var iterations = (int)Math.Ceiling((double)outputLengthBytes / hmacLengthBytes);

        var result = new byte[outputLengthBytes];
        var offset = 0;

        for (int i = 1; i <= iterations; i++)
        {
            // Counter as 32-bit big-endian as specified in SP 800-56C
            var counter = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(counter);

            // Construct input: Counter || Z || OtherInfo
            var inputData = new byte[counter.Length + sharedSecret.Length + otherInfo.Length];
            Array.Copy(counter, 0, inputData, 0, counter.Length);
            Array.Copy(sharedSecret, 0, inputData, counter.Length, sharedSecret.Length);
            Array.Copy(otherInfo, 0, inputData, counter.Length + sharedSecret.Length, otherInfo.Length);

            hmacAlgorithm.BlockUpdate(inputData, 0, inputData.Length);
            var hmacOutput = new byte[hmacLengthBytes];
            hmacAlgorithm.DoFinal(hmacOutput, 0);

            var bytesToCopy = Math.Min(hmacOutput.Length, outputLengthBytes - offset);
            Array.Copy(hmacOutput, 0, result, offset, bytesToCopy);
            offset += bytesToCopy;
        }

        return result;
    }

    /// <summary>
    /// Derives key material using the SP 800-56C HMAC-based KDF with a specified algorithm name.
    /// </summary>
    /// <param name="sharedSecret">The shared secret (Z) obtained from key agreement.</param>
    /// <param name="otherInfo">Additional information used in key derivation.</param>
    /// <param name="outputLengthBytes">The desired length of the derived key material in bytes.</param>
    /// <param name="hmacAlgorithmName">
    /// The name of the HMAC algorithm to use. Supported values: "HMAC-SHA1", "HMAC-SHA256", 
    /// "HMAC-SHA384", "HMAC-SHA512", "HMACSHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512".
    /// </param>
    /// <param name="salt">Optional salt value. If null, a zero-filled salt is used.</param>
    /// <returns>A byte array containing the derived key material of the specified length.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when an unsupported HMAC algorithm name is specified.
    /// </exception>
    public static byte[] DeriveKeyMaterial(
        byte[] sharedSecret, 
        byte[] otherInfo, 
        int outputLengthBytes, 
        string hmacAlgorithmName,
        byte[]? salt = null)
    {
        var hmacAlgorithm = CreateHmacAlgorithm(hmacAlgorithmName);
        return DeriveKeyMaterial(sharedSecret, otherInfo, outputLengthBytes, hmacAlgorithm, salt);
    }

    /// <summary>
    /// Creates an HMAC algorithm instance based on the specified algorithm name.
    /// </summary>
    /// <param name="hmacAlgorithmName">The name of the HMAC algorithm.</param>
    /// <returns>A Bouncy Castle HMAC instance for the specified algorithm.</returns>
    /// <exception cref="ArgumentException">Thrown when an unsupported algorithm name is specified.</exception>
    private static IMac CreateHmacAlgorithm(string hmacAlgorithmName)
    {
        return hmacAlgorithmName?.ToUpperInvariant() switch
        {
            "HMAC-SHA1" or "HMACSHA1" => new HMac(Sp80056COneStep.CreateDigest(NistHashAlgorithm.Sha1)),
            "HMAC-SHA256" or "HMACSHA256" => new HMac(Sp80056COneStep.CreateDigest(NistHashAlgorithm.Sha256)),
            "HMAC-SHA384" or "HMACSHA384" => new HMac(Sp80056COneStep.CreateDigest(NistHashAlgorithm.Sha384)),
            "HMAC-SHA512" or "HMACSHA512" => new HMac(Sp80056COneStep.CreateDigest(NistHashAlgorithm.Sha512)),
            _ => throw new ArgumentException($"Unsupported HMAC algorithm: {hmacAlgorithmName}", nameof(hmacAlgorithmName))
        };
    }
}
