// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System;

#endregion

namespace Kdf108.Domain.Kdf;

/// <summary>
///     Provides a fluent builder for constructing instances of <see cref="KdfOptions" />.
/// </summary>
/// <remarks>
///     This class simplifies the configuration and instantiation of <see cref="KdfOptions" /> by
///     offering a series of chainable methods. Each method modifies specific properties of
///     the underlying <see cref="KdfOptions" /> object.
/// </remarks>
public sealed class KdfOptionsBuilder
{
    /// <summary>
    ///     Represents the current configuration options for a Key Derivation Function (KDF)
    ///     being built by the <see cref="KdfOptionsBuilder" />.
    /// </summary>
    private KdfOptions _options = new();

    /// <summary>
    ///     Configures the key derivation options to use the specified pseudorandom function (PRF) type.
    /// </summary>
    /// <param name="prfType">The pseudorandom function (PRF) type to be used for key derivation.</param>
    /// <returns>A <see cref="KdfOptionsBuilder" /> instance configured with the specified PRF type.</returns>
    public KdfOptionsBuilder WithPrfType(PrfType prfType) => With(options => options with { PrfType = prfType });

    /// <summary>
    ///     Configures the number of bits to be used for the counter in the Key Derivation Function (KDF).
    /// </summary>
    /// <param name="bits">The length of the counter in bits. Typically, values are 8, 16, 24, or 32.</param>
    /// <returns>The current instance of <see cref="KdfOptionsBuilder" /> for method chaining.</returns>
    public KdfOptionsBuilder WithCounterLengthBits(int bits) =>
        With(options => options with { CounterLengthBits = bits });

    /// <summary>
    ///     Sets the initialization vector (IV) for the Key Derivation Function (KDF).
    /// </summary>
    /// <param name="iv">The initialization vector. Must be a byte array.</param>
    /// <returns>The current instance of <see cref="KdfOptionsBuilder" /> for method chaining.</returns>
    public KdfOptionsBuilder WithIv(byte[] iv) => With(options => options with { Iv = iv });

    /// <summary>
    ///     Specifies whether the key derivation function should use a counter mechanism.
    /// </summary>
    /// <param name="useCounter">A boolean value indicating whether to enable the counter functionality.</param>
    /// <return>The <see cref="KdfOptionsBuilder" /> instance with updated configuration.</return>
    public KdfOptionsBuilder WithUseCounter(bool useCounter) =>
        With(options => options with { UseCounter = useCounter });

    /// <summary>
    ///     Configures the location of the counter in the Key Derivation Function (KDF) input.
    /// </summary>
    /// <param name="location">
    ///     The desired location of the counter. It specifies whether the counter is placed before, after,
    ///     or in the middle of the fixed data.
    /// </param>
    /// <returns>The current <see cref="KdfOptionsBuilder" /> instance with the updated counter location configuration.</returns>
    public KdfOptionsBuilder WithCounterLocation(CounterLocation location) =>
        With(options => options with { CounterLocation = location });

    /// <summary>
    ///     Sets the maximum allowed number of bits for the KDF operation and updates the builder instance.
    /// </summary>
    /// <param name="maxBits">
    ///     The maximum number of bits that are allowed for the key derivation function. The value must be a positive long
    ///     integer.
    /// </param>
    /// <returns>
    ///     An updated instance of <see cref="KdfOptionsBuilder" /> with the specified maximum bits allowed set in the options.
    /// </returns>
    public KdfOptionsBuilder WithMaxBitsAllowed(long maxBits) =>
        With(options => options with { MaxBitsAllowed = maxBits });

    /// <summary>
    ///     Configures the KDF options for Counter Mode operation.
    /// </summary>
    /// <returns>
    ///     The current instance of <see cref="KdfOptionsBuilder" />.
    /// </returns>
    public KdfOptionsBuilder ForCounterMode() => With(options =>
        options with { UseCounter = true, CounterLocation = CounterLocation.BeforeFixed });

    /// <summary>
    ///     Configures the KDF options for feedback mode. This mode does not use a counter
    ///     and allows an optional initialization vector (IV) to be specified.
    /// </summary>
    /// <param name="iv">
    ///     An optional initialization vector (IV) represented as a byte array. This parameter
    ///     can be null if no IV is necessary for configuration.
    /// </param>
    /// <returns>The updated <see cref="KdfOptionsBuilder" /> instance with configurations for feedback mode.</returns>
    public KdfOptionsBuilder ForFeedbackMode(byte[]? iv = null) =>
        With(options => options with { UseCounter = false, Iv = iv });

    /// Configures the KdfOptions for double pipeline mode. In this mode,
    /// the UseCounter property is set to false, indicating that a counter
    /// is not utilized during the key derivation process.
    /// <returns>A KdfOptionsBuilder instance configured for double pipeline mode.</returns>
    public KdfOptionsBuilder ForDoublePipelineMode() => With(options => options with { UseCounter = false });

    /// <summary>
    ///     Finalizes and constructs a KdfOptions instance with the current configuration settings.
    /// </summary>
    /// <returns>A KdfOptions object containing the accumulated configuration options.</returns>
    public KdfOptions Build() => _options;

    /// <summary>
    ///     Configures and updates the current instance of the builder with the specified modifications.
    /// </summary>
    /// <param name="modifier">A function that applies changes to the current KdfOptions and returns an updated instance.</param>
    /// <returns>The same instance of <see cref="KdfOptionsBuilder" /> with the applied modifications.</returns>
    private KdfOptionsBuilder With(Func<KdfOptions, KdfOptions> modifier)
    {
        _options = modifier(_options);
        return this;
    }
}
