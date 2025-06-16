// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System;
using System.Collections.Generic;
using Kdf108.Domain.Interfaces.Kdf;
using Kdf108.Domain.Kdf.Modes;
using FunctionalExtensions = Kdf108.Infrastructure.FunctionalExtensions;

#endregion

namespace Kdf108.Domain.Kdf
{
    /// <summary>
    ///     The KdfEngine class provides methods to derive keys using various Key Derivation Function (KDF) modes.
    ///     This class supports different key derivation strategies as specified in the <see cref="KdfMode" /> enumeration.
    /// </summary>
    /// <remarks>
    ///     Key derivation is a critical operation in cryptographic applications to ensure secure and deterministic generation
    ///     of cryptographic keys.
    ///     The <see cref="Derive" /> method supports customizable parameters such as label, context, output key length, and
    ///     KDF options for flexible integration.
    /// </remarks>
    public static class KdfEngine
    {
        /// <summary>
        ///     A static, immutable dictionary mapping <see cref="KdfMode" /> values to
        ///     factory functions responsible for creating specific implementations of the
        ///     <see cref="IKdf" /> interface.
        /// </summary>
        /// <remarks>
        ///     The dictionary serves as a factory for constructing key derivation function (KDF) instances,
        ///     based on the specified <see cref="KdfMode" />. Each entry in the dictionary maps a derived
        ///     mode to the appropriate factory function that creates an instance of the respective
        ///     KDF implementation.
        /// </remarks>
        /// <example>
        ///     The factories support creating KDF instances such as <see cref="CounterModeKdf" />,
        ///     <see cref="FeedbackModeKdf" />, and <see cref="DoublePipelineKdf" />, each of which provides
        ///     specialized behavior based on a specific key derivation scheme.
        /// </example>
        /// <seealso cref="IKdf" />
        /// <seealso cref="KdfMode" />
        private static readonly Dictionary<KdfMode, Func<bool, IKdf>> s_kdfFactories =
            new()
            {
                [KdfMode.Counter] = _ => new CounterModeKdf(),
                [KdfMode.Feedback] = useCounter => new FeedbackModeKdf(useCounter),
                [KdfMode.DoublePipeline] = useCounter => new DoublePipelineKdf(useCounter)
            };

        /// <summary>
        ///     Derives a key from the provided inputs using the specified key derivation function (KDF) mode and options.
        /// </summary>
        /// <param name="mode">The key derivation function mode to be used for deriving the key.</param>
        /// <param name="kdk">The key derivation key (KDK), which acts as the base input for key generation.</param>
        /// <param name="label">A label string used to differentiate derived keys.</param>
        /// <param name="context">Additional context information to include in the key derivation process.</param>
        /// <param name="outputLengthInBits">The desired length of the derived key in bits.</param>
        /// <param name="options">
        ///     Additional options for configuring the key derivation process, such as PRF type, counter usage,
        ///     and input vector.
        /// </param>
        /// <returns>Returns the derived key as a byte array of the specified length.</returns>
        public static byte[] Derive(
            KdfMode mode,
            byte[] kdk,
            string label,
            byte[] context,
            int outputLengthInBits,
            KdfOptions options) =>
            FunctionalExtensions.Bind(
                FunctionalExtensions.Bind(DecomposeMode(mode),
                    modeParams => CreateKdf(modeParams.baseMode, modeParams.useCounter)),
                kdf => kdf.DeriveKey(kdk, label, context, outputLengthInBits, options));

        /// <summary>
        ///     Decomposes the provided key derivation function (KDF) mode into its base mode and identifies whether a counter is
        ///     used.
        /// </summary>
        /// <param name="mode">The key derivation mode to be decomposed.</param>
        /// <returns>
        ///     A tuple containing the base KDF mode and a boolean value indicating whether the mode uses a counter.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        ///     Thrown when the provided KDF mode is unsupported or invalid.
        /// </exception>
        private static (KdfMode baseMode, bool useCounter) DecomposeMode(KdfMode mode) =>
            mode switch
            {
                KdfMode.Counter => (KdfMode.Counter, false),
                KdfMode.Feedback => (KdfMode.Feedback, false),
                KdfMode.FeedbackWithCounter => (KdfMode.Feedback, true),
                KdfMode.DoublePipeline => (KdfMode.DoublePipeline, false),
                KdfMode.DoublePipelineWithCounter => (KdfMode.DoublePipeline, true),
                _ => throw new ArgumentOutOfRangeException(nameof(mode), $"Unsupported KDF mode: {mode}")
            };

        /// <summary>
        ///     Creates an instance of a Key Derivation Function (KDF) based on the provided base mode and counter usage option.
        /// </summary>
        /// <param name="baseMode">The base mode of the KDF. Determines the type of key derivation algorithm to use.</param>
        /// <param name="useCounter">A boolean value indicating whether to enable counter mode functionality.</param>
        /// <returns>An instance of <see cref="IKdf" /> representing the specified KDF configuration.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when the specified base mode is unsupported.</exception>
        private static IKdf CreateKdf(KdfMode baseMode, bool useCounter) =>
            s_kdfFactories.TryGetValue(baseMode, out Func<bool, IKdf>? factory)
                ? factory(useCounter)
                : throw new ArgumentOutOfRangeException(nameof(baseMode), $"Unsupported KDF mode: {baseMode}");
    }
}
