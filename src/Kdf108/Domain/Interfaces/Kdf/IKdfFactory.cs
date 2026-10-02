// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using Kdf108.Domain.Kdf;

namespace Kdf108.Domain.Interfaces.Kdf;

/// <summary>
/// Factory interface for creating KDF instances.
/// </summary>
public interface IKdfFactory
{
    /// <summary>
    /// Creates a KDF instance for the specified mode.
    /// </summary>
    /// <param name="mode">The KDF mode to create.</param>
    /// <param name="useCounter">Whether to use counter in feedback/double-pipeline modes.</param>
    /// <returns>A KDF instance configured for the specified mode.</returns>
    IKdf CreateKdf(KdfMode mode, bool useCounter = false);
}
