// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

namespace Kdf108.Domain.Kdf;

/// <summary>
/// Represents a request for performing key derivation.
/// This class encapsulates the parameters needed for a Key Derivation Function (KDF) operation,
/// including the key derivation key, label, context, output length, and additional options.
/// </summary>
public sealed class KdfRequest
{
    /// <summary>
    /// Represents a request containing the input parameters required for a
    /// Key Derivation Function (KDF) operation.
    /// </summary>
    /// <remarks>
    /// A KDF is used to derive one or more cryptographic keys from a given
    /// input keying material and additional parameters.
    /// This class holds all necessary inputs for performing a KDF operation.
    /// </remarks>
    public KdfRequest(
        byte[] keyDerivationKey,
        string label,
        byte[] context,
        long outputLengthBits,
        KdfOptions options)
    {
        KeyDerivationKey = keyDerivationKey;
        Label = label;
        Context = context;
        OutputLengthBits = outputLengthBits;
        Options = options;
    }

    /// <summary>
    /// Represents the base key used for the key derivation process.
    /// This key serves as the input material from which derived keys
    /// are generated according to the specified Key Derivation Function (KDF) algorithm.
    /// The key must not be null or empty to ensure the validity
    /// and security of the key derivation process.
    /// </summary>
    public byte[] KeyDerivationKey { get; set; }

    /// <summary>
    /// Gets or sets the label associated with the key derivation process.
    /// </summary>
    /// <remarks>
    /// The label is an optional string used in the key derivation function
    /// as a distinguishing identifier for the derived keys.
    /// </remarks>
    /// <exception cref="Kdf108.Exceptions.KdfValidationException">
    /// Thrown when the value is null, as Label is a required property.
    /// </exception>
    public string Label { get; set; }

    /// <summary>
    /// Gets or sets the context data used in the key derivation function (KDF) process.
    /// The context is an optional input that provides additional information to the KDF,
    /// typically used to differentiate derived keys for distinct purposes or systems.
    /// </summary>
    /// <remarks>
    /// This property must not be null, as validated by the <see cref="Kdf108.Domain.Validator.KdfRequestValidator"/>.
    /// The context may be used by certain KDF implementations and ignored by others
    /// depending on the specified key derivation function and parameters.
    /// </remarks>
    public byte[] Context { get; set; }

    /// <summary>
    /// Specifies the desired output length in bits for the key derivation function (KDF) operation.
    /// </summary>
    /// <remarks>
    /// The value must be greater than 0 and should not exceed the maximum allowed bits as specified in the
    /// <see cref="KdfOptions.MaxBitsAllowed"/> property of the associated <see cref="KdfOptions"/>.
    /// This property is validated to ensure that the requested output length aligns with the KDF configuration.
    /// </remarks>
    public long OutputLengthBits { get; set; }

    /// <summary>
    /// Gets or sets the Key Derivation Function (KDF) configuration options associated with the request.
    /// </summary>
    /// <remarks>
    /// This property specifies various configurable parameters for the KDF, such as the pseudorandom function
    /// (PRF) type, counter behavior, and maximum allowable output length. It is essential for defining the
    /// behavior and characteristics of the key derivation process.
    /// The provided configuration must be valid and adhere to any relevant constraints, such as the
    /// counter length being within the supported range (1 to 32 bits).
    /// </remarks>
    public KdfOptions Options { get; set; }
}
