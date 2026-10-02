// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Threading;
using System.Threading.Tasks;
using Kdf108.Domain.Kdf;

namespace Kdf108.Domain.Interfaces.Kdf;

/// <summary>
///     Interface for key derivation functions that generate keying material from a key-derivation key.
/// </summary>
public interface IKdf
{
    /// <summary>
    ///     Derives a key using the key-derivation function.
    /// </summary>
    /// <param name="kdk">The key-derivation key.</param>
    /// <param name="label">A string that identifies the purpose for the derived keying material.</param>
    /// <param name="context">Context information related to the derived keying material.</param>
    /// <param name="outputLengthInBits">The length of the derived keying material in bits.</param>
    /// <param name="options">Options for configuring the key derivation function.</param>
    /// <returns>The derived keying material.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when a parameter has an invalid value.</exception>
    /// <exception cref="FluentValidation.ValidationException">Thrown when validation fails.</exception>
    byte[] DeriveKey(byte[] kdk, string label, byte[] context, long outputLengthInBits, KdfOptions options);

    /// <summary>
    ///     Asynchronously derives a key using the key-derivation function.
    /// </summary>
    /// <param name="kdk">The key-derivation key.</param>
    /// <param name="label">A string that identifies the purpose for the derived keying material.</param>
    /// <param name="context">Context information related to the derived keying material.</param>
    /// <param name="outputLengthInBits">The length of the derived keying material in bits.</param>
    /// <param name="options">Options for configuring the key derivation function.</param>
    /// <param name="cancellationToken">A cancellation token that can be used to cancel the operation.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the derived keying material.</returns>
    /// <exception cref="ArgumentNullException">Thrown when a required parameter is null.</exception>
    /// <exception cref="ArgumentException">Thrown when a parameter has an invalid value.</exception>
    /// <exception cref="FluentValidation.ValidationException">Thrown when validation fails.</exception>
    Task<byte[]> DeriveKeyAsync(byte[] kdk, string label, byte[] context, long outputLengthInBits, KdfOptions options, CancellationToken cancellationToken = default);
}

