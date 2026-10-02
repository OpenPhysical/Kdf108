// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

namespace Kdf108.Domain.Kdf;

/// <summary>
/// Defines the types of pseudorandom functions (PRFs) supported for key derivation.
/// </summary>
/// <remarks>
/// This enumeration specifies the various cryptographic algorithms that can be used as PRFs
/// in key derivation functions (KDFs). The PRF is a critical component that provides the
/// cryptographic strength and security properties of the derived keys.
/// </remarks>
public enum PrfType
{
    // HMAC PRFs
    /// <summary>
    /// Represents the HMAC-SHA-1 pseudorandom function (PRF) type used for key derivation functions.
    /// </summary>
    HmacSha1,

    /// <summary>
    /// Represents the HMAC (Hash-based Message Authentication Code) using the SHA-224 hashing algorithm
    /// as a pseudorandom function (PRF) type for key derivation processes.
    /// </summary>
    HmacSha224,

    /// <summary>
    /// Specifies the HMAC-SHA256 algorithm as a pseudorandom function (PRF) for key derivation.
    /// </summary>
    /// <remarks>
    /// HMAC-SHA256 is a cryptographic function that combines a hash function (SHA-256) with a secret key,
    /// providing a secure and widely used option for generating pseudorandom values in key derivation.
    /// </remarks>
    HmacSha256,

    /// <summary>
    /// Specifies the HMAC-SHA-384 pseudorandom function type for key derivation.
    /// </summary>
    /// <remarks>
    /// HMAC-SHA-384 is a cryptographic hash function that provides 384 bits of output,
    /// offering a higher level of security than SHA-256 while being more efficient than SHA-512
    /// in certain applications.
    /// </remarks>
    HmacSha384,

    /// <summary>
    /// Specifies the HMAC-SHA-512 pseudorandom function type for key derivation.
    /// </summary>
    /// <remarks>
    /// HMAC-SHA-512 is a cryptographic hash function used to generate pseudorandom output
    /// for secure key derivation processes. It provides a balance of strong cryptographic
    /// properties and industry standard compliance.
    /// </remarks>
    HmacSha512,

    /// <summary>HMAC using SHA-512/224.</summary>
    HmacSha512_224,

    /// <summary>HMAC using SHA-512/256.</summary>
    HmacSha512_256,

    /// <summary>HMAC using SHA3-224.</summary>
    HmacSha3_224,

    /// <summary>HMAC using SHA3-256.</summary>
    HmacSha3_256,

    /// <summary>HMAC using SHA3-384.</summary>
    HmacSha3_384,

    /// <summary>HMAC using SHA3-512.</summary>
    HmacSha3_512,

    // CMAC PRFs
    /// <summary>
    /// Specifies the CMAC-AES-128 (Cipher-based Message Authentication Code with 128-bit AES)
    /// pseudorandom function type for key derivation.
    /// </summary>
    /// <remarks>
    /// CMAC-AES-128 uses the AES block cipher with a 128-bit key to generate pseudorandom output
    /// suitable for key derivation functions.
    /// </remarks>
    CmacAes128,

    /// <summary>
    /// Specifies the CMAC-AES-192 (Cipher-based Message Authentication Code with 192-bit AES)
    /// pseudorandom function type for key derivation.
    /// </summary>
    /// <remarks>
    /// CMAC-AES-192 uses the AES block cipher with a 192-bit key to generate pseudorandom output
    /// for secure key derivation processes.
    /// </remarks>
    CmacAes192,

    /// <summary>
    /// Specifies the CMAC-AES-256 (Cipher-based Message Authentication Code with 256-bit AES)
    /// pseudorandom function type for key derivation.
    /// </summary>
    CmacAes256,

    /// <summary>
    /// Specifies the CMAC-TDES-3 (Cipher-based Message Authentication Code with three-key TDES)
    /// pseudorandom function type for key derivation.
    /// </summary>
    /// <remarks>
    /// CMAC-TDES-3 uses the Triple Data Encryption Standard with three independent 56-bit keys
    /// (168 bits total) to provide backward compatibility with legacy systems while maintaining
    /// reasonable security properties.
    /// </remarks>
    CmacTdes3,

    /// <summary>
    /// Specifies the CMAC-TDES-2 (Cipher-based Message Authentication Code with two-key TDES)
    /// pseudorandom function type for key derivation.
    /// </summary>
    /// <remarks>
    /// CMAC-TDES-2 uses the Triple Data Encryption Standard with two independent 56-bit keys
    /// (112 bits total) for environments requiring TDES compatibility with reduced key material.
    /// </remarks>
    CmacTdes2
}
