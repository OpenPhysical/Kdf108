// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

namespace Kdf108.Domain.Interfaces.Prf;

/// <summary>
///     Interface for Pseudorandom Functions (PRF) used in key derivation functions
/// </summary>
public interface IPrf
{
    /// <summary>
    ///     Gets the number of bits output per invocation of the PRF.
    ///     This is typically the size of the MAC output for PRFs.
    /// </summary>
    int OutputSizeBits { get; }

    /// <summary>
    ///     Computes the PRF over the given data using the provided key.
    /// </summary>
    /// <param name="key">The secret key input to the PRF.</param>
    /// <param name="data">The data to be processed.</param>
    /// <returns>The derived pseudorandom output.</returns>
    byte[] Compute(byte[] key, byte[] data);
}
