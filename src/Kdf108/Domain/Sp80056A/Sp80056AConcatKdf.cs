// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Security.Cryptography;
using Kdf108.Infrastructure.Cryptography;

namespace Kdf108.Domain.Sp80056A;

/// <summary>
/// Implements the Concatenation Key Derivation Function (Concat KDF) as specified in NIST SP 800-56A Rev 3, Section 5.8.1.
/// This KDF is used to derive key material from a shared secret obtained through a key agreement scheme.
/// </summary>
/// <remarks>
/// The Concat KDF implements the following algorithm:
/// KDF(Z, OtherInfo) = H(0x00000001 || Z || OtherInfo) || H(0x00000002 || Z || OtherInfo) || ...
/// where H is an approved hash function and the counter is a 32-bit big-endian integer.
/// </remarks>
public static class Sp80056AConcatKdf
{
    /// <summary>
    /// Derives key material using the SP 800-56A Concatenation KDF.
    /// </summary>
    /// <param name="sharedSecret">The shared secret (Z) obtained from key agreement.</param>
    /// <param name="otherInfo">
    /// Additional information used in key derivation. This typically includes algorithm identifiers,
    /// key usage information, and other context-specific data.
    /// </param>
    /// <param name="outputLengthBytes">The desired length of the derived key material in bytes.</param>
    /// <param name="hashAlgorithm">The hash algorithm to use for the KDF. Must be an approved algorithm.</param>
    /// <returns>A byte array containing the derived key material of the specified length.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when any of the required parameters are null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when the output length is zero or negative, or when an unsupported hash algorithm is specified.
    /// </exception>
    public static byte[] DeriveKeyMaterial(byte[] sharedSecret, byte[] otherInfo, int outputLengthBytes, HashAlgorithm hashAlgorithm)
    {
        if (sharedSecret == null)
            throw new ArgumentNullException(nameof(sharedSecret));
        if (otherInfo == null)
            throw new ArgumentNullException(nameof(otherInfo));
        if (hashAlgorithm == null)
            throw new ArgumentNullException(nameof(hashAlgorithm));
        if (outputLengthBytes <= 0)
            throw new ArgumentException("Output length must be positive", nameof(outputLengthBytes));

        var hashLengthBytes = hashAlgorithm.HashSize / 8;
        var iterations = (int)Math.Ceiling((double)outputLengthBytes / hashLengthBytes);

        var result = new byte[outputLengthBytes];
        var offset = 0;

        for (int i = 1; i <= iterations; i++)
        {
            // Counter as 32-bit big-endian as specified in SP 800-56A
            var counter = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(counter);

            // Construct input: Counter || Z || OtherInfo
            var inputData = new byte[counter.Length + sharedSecret.Length + otherInfo.Length];
            Array.Copy(counter, 0, inputData, 0, counter.Length);
            Array.Copy(sharedSecret, 0, inputData, counter.Length, sharedSecret.Length);
            Array.Copy(otherInfo, 0, inputData, counter.Length + sharedSecret.Length, otherInfo.Length);

            var hashOutput = hashAlgorithm.ComputeHash(inputData);

            var bytesToCopy = Math.Min(hashOutput.Length, outputLengthBytes - offset);
            Array.Copy(hashOutput, 0, result, offset, bytesToCopy);
            offset += bytesToCopy;
        }

        return result;
    }

    /// <summary>
    /// Derives key material using the SP 800-56A Concatenation KDF with a specified hash algorithm name.
    /// </summary>
    /// <param name="sharedSecret">The shared secret (Z) obtained from key agreement.</param>
    /// <param name="otherInfo">Additional information used in key derivation.</param>
    /// <param name="outputLengthBytes">The desired length of the derived key material in bytes.</param>
    /// <param name="hashAlgorithmName">
    /// The name of the hash algorithm to use. Supported values: "SHA1", "SHA-1", "SHA224", "SHA-224", 
    /// "SHA256", "SHA-256", "SHA384", "SHA-384", "SHA512", "SHA-512".
    /// </param>
    /// <returns>A byte array containing the derived key material of the specified length.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when an unsupported hash algorithm name is specified.
    /// </exception>
    public static byte[] DeriveKeyMaterial(byte[] sharedSecret, byte[] otherInfo, int outputLengthBytes, string hashAlgorithmName)
    {
        using var hashAlgorithm = CreateHashAlgorithm(hashAlgorithmName);
        return DeriveKeyMaterial(sharedSecret, otherInfo, outputLengthBytes, hashAlgorithm);
    }

    /// <summary>
    /// Creates a hash algorithm instance based on the specified algorithm name.
    /// </summary>
    /// <param name="hashAlgorithmName">The name of the hash algorithm.</param>
    /// <returns>A HashAlgorithm instance for the specified algorithm.</returns>
    /// <exception cref="ArgumentException">Thrown when an unsupported algorithm name is specified.</exception>
    private static HashAlgorithm CreateHashAlgorithm(string hashAlgorithmName)
    {
        return hashAlgorithmName switch
        {
            "SHA1" => SHA1.Create(),
            "SHA-1" => SHA1.Create(),
            "SHA224" => new Sha224HashAlgorithm(),
            "SHA-224" => new Sha224HashAlgorithm(),
            "SHA256" => SHA256.Create(),
            "SHA-256" => SHA256.Create(),
            "SHA384" => SHA384.Create(),
            "SHA-384" => SHA384.Create(),
            "SHA512" => SHA512.Create(),
            "SHA-512" => SHA512.Create(),
            _ => throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithmName}", nameof(hashAlgorithmName))
        };
    }
}