// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using Kdf108.Domain.Sp80056A;
using Kdf108.Domain.Sp80056C;

namespace Kdf108.Domain.Interfaces.KeyAgreement;

/// <summary>
/// Interface for key derivation pipelines as defined in NIST SP 800-56C.
/// Combines key agreement (SP 800-56A) with key derivation (SP 800-108).
/// </summary>
internal interface ISp80056CKeyDerivationPipeline
{
    /// <summary>
    /// Performs key agreement and derives keys using the complete pipeline.
    /// </summary>
    /// <param name="localPrivateKey">The local party's private key.</param>
    /// <param name="remotePublicKey">The remote party's public key.</param>
    /// <param name="options">Pipeline configuration options.</param>
    /// <returns>The derived key material.</returns>
    byte[] DeriveKey(
        Sp80056APrivateKey localPrivateKey,
        Sp80056APublicKey remotePublicKey,
        Sp80056COptions options);

    /// <summary>
    /// Performs key derivation from an existing shared secret.
    /// </summary>
    /// <param name="sharedSecret">The shared secret from key agreement.</param>
    /// <param name="options">Pipeline configuration options.</param>
    /// <returns>The derived key material.</returns>
    byte[] DeriveKeyFromSharedSecret(
        byte[] sharedSecret,
        Sp80056COptions options);

    /// <summary>
    /// Gets the name of the pipeline implementation.
    /// </summary>
    string PipelineName { get; }
}
