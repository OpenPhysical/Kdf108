// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108.Domain.Interfaces.KeyAgreement;

/// <summary>
/// Interface for key agreement schemes as defined in NIST SP 800-56A.
/// Provides methods for performing key agreement operations between two parties.
/// </summary>
public interface ISp80056AKeyAgreement
{
    /// <summary>
    /// Performs key agreement between a local private key and a remote public key.
    /// </summary>
    /// <param name="localPrivateKey">The local party's private key.</param>
    /// <param name="remotePublicKey">The remote party's public key.</param>
    /// <returns>The shared secret derived from the key agreement.</returns>
    /// <exception cref="ArgumentNullException">Thrown when either key is null.</exception>
    /// <exception cref="ArgumentException">Thrown when keys are invalid or incompatible.</exception>
    byte[] PerformKeyAgreement(byte[] localPrivateKey, byte[] remotePublicKey);

    /// <summary>
    /// Validates that the provided keys are suitable for key agreement.
    /// </summary>
    /// <param name="privateKey">The private key to validate.</param>
    /// <param name="publicKey">The public key to validate.</param>
    /// <returns>True if the keys are valid and compatible, false otherwise.</returns>
    bool ValidateKeys(byte[] privateKey, byte[] publicKey);

    /// <summary>
    /// Gets the expected size of the shared secret in bytes.
    /// </summary>
    int SharedSecretSize { get; }

    /// <summary>
    /// Gets the name of the key agreement scheme (e.g., "ECDH-P256", "ECDH-P384").
    /// </summary>
    string SchemeName { get; }
}
