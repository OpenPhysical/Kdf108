// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
#region

using System;
using JetBrains.Annotations;

#endregion

namespace Kdf108.Domain.Kdf
{
    /// <summary>
    /// Provides a fluent builder for constructing and configuring <see cref="KdfOptions" /> instances.
    /// </summary>
    /// <remarks>
    /// This class allows developers to configure various properties of a <see cref="KdfOptions" />
    /// object using a chainable API, thereby enabling intuitive and flexible construction.
    /// </remarks>
    [PublicAPI]
    public sealed class KdfOptionsBuilder
    {
        /// <summary>
        /// Holds the current configuration options for a Key Derivation Function (KDF)
        /// being constructed using the <see cref="KdfOptionsBuilder" />.
        /// </summary>
        private KdfOptions _options = new KdfOptions();

        /// <summary>
        /// Sets the pseudorandom function (PRF) type for the key derivation process.
        /// </summary>
        /// <param name="prfType">The <see cref="PrfType"/> specifying the desired PRF type.</param>
        /// <returns>An updated instance of <see cref="KdfOptionsBuilder"/> for further configuration.</returns>
        public KdfOptionsBuilder WithPrfType(PrfType prfType) =>
            With(options => options.PrfType = prfType);

        /// <summary>
        /// Sets the length of the counter in bits for the key derivation function configuration.
        /// </summary>
        /// <param name="bits">
        /// The desired length of the counter in bits. This value determines the size of the counter
        /// used in the key derivation process.
        /// </param>
        /// <returns>
        /// An updated instance of <see cref="KdfOptionsBuilder"/> with the specified counter length applied.
        /// </returns>
        public KdfOptionsBuilder WithCounterLengthBits(int bits) =>
            With(options => options.CounterLengthBits = bits);

        /// <summary>
        /// Sets the Initialization Vector (IV) for the Key Derivation Function (KDF) options.
        /// </summary>
        /// <param name="iv">A byte array representing the Initialization Vector (IV) to be used during key derivation. Can be null if not required.</param>
        /// <returns>The current instance of <see cref="KdfOptionsBuilder"/> with the IV value set.</returns>
        public KdfOptionsBuilder WithIv(byte[] iv) =>
            With(options => options.Iv = iv);

        /// <summary>
        /// Configures the KDF options to specify whether a counter is used in key derivation.
        /// </summary>
        /// <param name="useCounter">
        /// A boolean value indicating whether the counter is used in the key derivation process.
        /// </param>
        /// <returns>
        /// The current instance of <see cref="KdfOptionsBuilder"/> to allow method chaining.
        /// </returns>
        public KdfOptionsBuilder WithUseCounter(bool useCounter) =>
            With(options => options.UseCounter = useCounter);

        /// <summary>
        /// Sets the location of the counter in the KDF input.
        /// </summary>
        /// <param name="location">The <see cref="CounterLocation"/> specifying where the counter should be placed in the KDF input.</param>
        /// <returns>A <see cref="KdfOptionsBuilder"/> instance for chaining additional configuration.</returns>
        public KdfOptionsBuilder WithCounterLocation(CounterLocation location) =>
            With(options => options.CounterLocation = location);

        /// <summary>
        /// Configures the maximum number of bits allowed for the key derivation function.
        /// </summary>
        /// <param name="maxBits">The maximum number of bits allowed.</param>
        /// <returns>An updated instance of <see cref="KdfOptionsBuilder"/> with the specified configuration applied.</returns>
        public KdfOptionsBuilder WithMaxBitsAllowed(long maxBits) =>
            With(options => options.MaxBitsAllowed = maxBits);

        /// <summary>
        /// Configures the KDF options specifically for the counter mode of operation.
        /// </summary>
        /// <returns>
        /// The <see cref="KdfOptionsBuilder"/> instance to enable method chaining during the configuration process.
        /// </returns>
        public KdfOptionsBuilder ForCounterMode() =>
            With(options =>
            {
                options.UseCounter = true;
                options.CounterLocation = CounterLocation.BeforeFixed;
            });

        /// <summary>
        /// Configures the <see cref="KdfOptionsBuilder"/> for feedback mode operation,
        /// optionally setting the initialization vector (IV).
        /// </summary>
        /// <param name="iv">The initialization vector (IV) to use, or null for default configuration.</param>
        /// <returns>The current instance of <see cref="KdfOptionsBuilder"/>, configured for feedback mode.</returns>
        public KdfOptionsBuilder ForFeedbackMode(byte[]? iv = null) =>
            With(options =>
            {
                options.UseCounter = false;
                options.Iv = iv;
            });

        /// <summary>
        /// Configures the current <see cref="KdfOptionsBuilder"/> instance for Double Pipeline Mode,
        /// where the counter mechanism is disabled.
        /// </summary>
        /// <returns>The current instance of <see cref="KdfOptionsBuilder"/> configured for Double Pipeline Mode.</returns>
        public KdfOptionsBuilder ForDoublePipelineMode() =>
            With(options => options.UseCounter = false);

        /// <summary>
        /// Completes the construction of a <see cref="KdfOptions"/> instance and returns the built object.
        /// </summary>
        /// <returns>
        /// A fully constructed instance of <see cref="KdfOptions"/> with the specified configurations.
        /// </returns>
        public KdfOptions Build() => _options;

        /// <summary>
        /// Modifies the internal state of the builder with the provided mutation action.
        /// This is a private helper method to apply transformations to the <see cref="KdfOptions"/> object.
        /// </summary>
        /// <param name="mutate">An action to apply specific configuration changes to the <see cref="KdfOptions"/> instance.</param>
        /// <returns>The updated instance of the <see cref="KdfOptionsBuilder"/> for chaining further method calls.</returns>
        private KdfOptionsBuilder With(Action<KdfOptions> mutate)
        {
            var copy = _options.Clone();
            mutate(copy);
            _options = copy;
            return this;
        }
    }
}
