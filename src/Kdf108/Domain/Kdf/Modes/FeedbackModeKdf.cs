// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using FluentValidation;
using FluentValidation.Results;
using Kdf108.Domain.Interfaces.Kdf;
using Kdf108.Domain.Interfaces.Prf;
using Kdf108.Domain.Validator;
using Kdf108.Infrastructure.Prf;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Kdf108.Domain.Kdf.Modes;

/// <summary>
/// Represents a Key Derivation Function (KDF) implementation in feedback mode, conforming to the KDF specifications.
/// FeedbackModeKdf is responsible for deriving cryptographic keys based on a key derivation key (KDK), a label, a context, and various other parameters.
/// </summary>
public sealed class FeedbackModeKdf : IKdf
{
    /// <summary>
    /// Static instance of <see cref="KdfRequestValidator"/> used for validating
    /// key derivation function (KDF) requests in the FeedbackModeKdf implementation.
    /// Ensures that input parameters adhere to the defined rules before proceeding
    /// with key derivation operations.
    /// </summary>
    private static readonly KdfRequestValidator s_validator = new();

    /// <summary>
    /// Indicates whether a counter is used during the key derivation process in the feedback mode KDF.
    /// Determines if a counter is included in the computation steps to help produce unique derived keys.
    /// </summary>
    private readonly bool _useCounter;

    /// <summary>
    /// Logger instance used for logging information, warnings, errors, or debugging messages
    /// within the <see cref="FeedbackModeKdf"/> class. If no logger is provided during
    /// instantiation, a <see cref="NullLogger{T}"/> instance is used as a fallback.
    /// </summary>
    private readonly ILogger<FeedbackModeKdf> _logger;

    /// Represents the Feedback Mode Key Derivation Function (KDF).
    /// This implementation supports an optional counter configuration and logging.
    /// Feedback Mode KDF is commonly used in cryptographic key derivation routines and operates
    /// by iteratively applying a pseudorandom function with feedback for generating derived keys.
    public FeedbackModeKdf(bool useCounter, ILogger<FeedbackModeKdf>? logger = null)
    {
        _useCounter = useCounter;
        _logger = logger ?? NullLogger<FeedbackModeKdf>.Instance;
    }

    /// <summary>
    /// Derives a cryptographic key from the specified inputs using the Feedback mode key derivation function (KDF).
    /// </summary>
    /// <param name="kdk">The key derivation key (KDK) used as the base for deriving a new key. Must not be null or empty.</param>
    /// <param name="label">A label that adds contextual information to the key derivation process. Cannot be null.</param>
    /// <param name="context">Optional contextual information used in the key derivation process. Can be null or empty.</param>
    /// <param name="outputLengthInBits">The desired length of the derived key in bits. Must be a positive integer.</param>
    /// <param name="options">Additional key derivation options, such as the pseudo-random function (PRF) type, counter settings, and initialization vector (IV). Cannot be null.</param>
    /// <returns>A byte array representing the derived key with the specified output length.</returns>
    public byte[] DeriveKey(byte[] kdk, string label, byte[] context, long outputLengthInBits, KdfOptions options) =>
        ValidateRequest(kdk, label, context, outputLengthInBits, options)
            .Bind(_ => CreateFixedInputData(label, context, outputLengthInBits))
            .Bind(fixedInput => DeriveBlocks(
                kdk,
                fixedInput,
                options.Iv ?? Array.Empty<byte>(),
                outputLengthInBits,
                options.PrfType,
                options.CounterLengthBits,
                options.CounterLocation,
                _useCounter
            ));

    /// <summary>
    /// Derives a key using a fixed input alongside the provided key derivation parameters,
    /// following the feedback mode-based key derivation function.
    /// </summary>
    /// <param name="kdk">The key derivation key (KDK) used as the primary input for the derivation process.</param>
    /// <param name="fixedInput">The fixed input value that provides context and additional entropy for the derivation.</param>
    /// <param name="iv">The initialization vector (IV), which can be null or empty for certain configurations.</param>
    /// <param name="outputLengthInBits">The desired length of the derived key output, specified in bits.</param>
    /// <param name="options">An instance of <see cref="KdfOptions"/> providing additional configuration such as PRF type, counter length, and counter location.</param>
    /// <returns>A byte array representing the derived key of the specified length.</returns>
    public byte[] DeriveWithFixedInput(byte[] kdk, byte[] fixedInput, byte[]? iv, long outputLengthInBits,
        KdfOptions options)
    {
        KdfInputValidator.ValidateFixedInput(kdk, fixedInput, outputLengthInBits, options);
        return DeriveBlocks(
            kdk,
            fixedInput,
            iv ?? new byte[0],
            outputLengthInBits,
            options.PrfType,
            options.CounterLengthBits,
            options.CounterLocation,
            _useCounter);
    }

    /// <summary>
    /// Validates a key derivation request and ensures that all required parameters are correct and comply with the expected rules.
    /// If the validation fails, an exception is thrown with the validation errors.
    /// </summary>
    /// <param name="kdk">The key derivation key (KDK) to be used in the derivation process.</param>
    /// <param name="label">A string label used as part of the key derivation input.</param>
    /// <param name="context">A byte array representing the context information relevant to the derived key.</param>
    /// <param name="outputLengthInBits">The desired length of the derived key in bits.</param>
    /// <param name="options">Additional options for the key derivation process, such as the pseudorandom function type and counter-related configurations.</param>
    /// <returns>A <c>KdfRequest</c> object containing the validated request parameters.</returns>
    /// <exception cref="ValidationException">Thrown when the validation of the input parameters fails.</exception>
    private KdfRequest ValidateRequest(byte[] kdk, string label, byte[] context, long outputLengthInBits,
        KdfOptions options)
    {
        KdfRequest request = new(
            kdk,
            label,
            context,
            outputLengthInBits,
            options);

        ValidationResult? result = s_validator.Validate(request);
        return result.IsValid
            ? request
            : throw new ValidationException(result.Errors);
    }

    /// <summary>
    /// Derives key blocks using the specified parameters.
    /// </summary>
    /// <param name="kdk">
    /// The key derivation key (KDK), a binary key used as the primary input to the key derivation process.
    /// </param>
    /// <param name="fixedInput">
    /// The fixed input data that is combined with the counter during the fixed-input derivation process.
    /// </param>
    /// <param name="iv">
    /// An optional initialization vector (IV) that may be used if defined by the key derivation algorithm.
    /// </param>
    /// <param name="outputLengthInBits">
    /// The desired length of the output key in bits.
    /// </param>
    /// <param name="prfType">
    /// The pseudorandom function (PRF) type used as the core cryptographic primitive for the key derivation process.
    /// </param>
    /// <param name="counterLengthBits">
    /// The number of bits used for the counter value during the key derivation.
    /// </param>
    /// <param name="counterLocation">
    /// The position of the counter within the fixed-input format, which specifies whether it appears before, after,
    /// or in the middle of the fixed input.
    /// </param>
    /// <param name="useCounter">
    /// Indicates whether the derivation process will include a counter as part of the fixed-input data.
    /// </param>
    /// <returns>
    /// A byte array representing the derived key material, truncated to the specified output length in bits.
    /// </returns>
    private static byte[] DeriveBlocks(
        byte[] kdk,
        byte[] fixedInput,
        byte[] iv,
        long outputLengthInBits,
        PrfType prfType,
        int counterLengthBits,
        CounterLocation counterLocation,
        bool useCounter)
    {
        IPrf prf = PrfFactory.Create(prfType);
        int outputSizeBits = prf.OutputSizeBits;
        int outputSizeBytes = outputSizeBits / 8;

        var (reps, _) = KdfOutputLimits.Validate(outputLengthInBits, outputSizeBits, counterLengthBits, useCounter);
        byte[] resultBuffer = GenerateBlocks(kdk, fixedInput, iv, reps, prf, outputSizeBytes, counterLengthBits, counterLocation, useCounter);
        try { return TruncateToRequestedLength(resultBuffer, outputLengthInBits); }
        finally { CryptographicOperations.ZeroMemory(resultBuffer); }
    }

    /// <summary>
    /// Validates the number of repetitions, counter length, requested output size, and whether counters are used.
    /// Ensures that the derived key parameters meet the constraints for both counter-based and non-counter-based Key Derivation Function (KDF) modes.
    /// </summary>
    /// <param name="reps">The number of blocks required to generate the requested output size.</param>
    /// <param name="counterLengthBits">The length of the counter in bits, used in counter-based KDF modes.</param>
    /// <param name="outputLengthInBits">The desired output length in bits for the derived key.</param>
    /// <param name="useCounter">Specifies if a counter is utilized in the KDF operation.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when the requested output size exceeds the counter limit in counter-based mode,
    /// or if the total output size exceeds the .NET buffer size limits.
    /// </exception>
    private static void ValidateCounterAndOutputSize(
        long reps, int counterLengthBits, long outputLengthInBits, bool useCounter)
    {
        if (useCounter)
        {
            long maxCounter = (1L << counterLengthBits) - 1;
            if (reps > maxCounter)
            {
                throw new ArgumentException(
                    $"Too much output requested — exceeds counter limit (2^{counterLengthBits} blocks).",
                    nameof(outputLengthInBits));
            }
        }

        long totalBytes = reps * (outputLengthInBits / 8 / reps);
        if (totalBytes > int.MaxValue)
        {
            throw new ArgumentException("Too much output requested — exceeds .NET buffer size limits.",
                nameof(outputLengthInBits));
        }
    }

    /// <summary>
    /// Generates key material by deriving blocks of data using a specified pseudorandom function (PRF),
    /// a key derivation key (KDK), and other configurable parameters.
    /// </summary>
    /// <param name="kdk">The key derivation key used as the input to the PRF.</param>
    /// <param name="fixedInput">The fixed input data used in the key derivation process.</param>
    /// <param name="iv">The initialization vector used to start the key derivation process.</param>
    /// <param name="reps">The number of iterations or repetitions for block generation.</param>
    /// <param name="prf">The pseudorandom function used to derive the key material.</param>
    /// <param name="outputSizeBytes">The size of each PRF output block in bytes.</param>
    /// <param name="counterLengthBits">The length of the counter in bits, if counters are used.</param>
    /// <param name="counterLocation">The location of the counter relative to the fixed input (e.g., before, after, or in the middle).</param>
    /// <param name="useCounter">Indicates whether counters are used in the key derivation process.</param>
    /// <returns>A byte array containing the derived key material up to the specified number of blocks.</returns>
    private static byte[] GenerateBlocks(
        byte[] kdk,
        byte[] fixedInput,
        byte[] iv,
        long reps,
        IPrf prf,
        int outputSizeBytes,
        int counterLengthBits,
        CounterLocation counterLocation,
        bool useCounter)
    {
        byte[] resultBuffer = new byte[checked((int)(reps * outputSizeBytes))];
        int offset = 0;
        byte[] currentK = (byte[])iv.Clone();

        try
        {
            for (uint i = 1; i <= reps; i++)
            {
                byte[] prfInput = CreatePrfInput(currentK, fixedInput, i, counterLengthBits, counterLocation, useCounter);
                byte[] nextK;
                try { nextK = prf.Compute(kdk, prfInput); }
                finally { CryptographicOperations.ZeroMemory(prfInput); }
                CryptographicOperations.ZeroMemory(currentK);
                currentK = nextK;
                Buffer.BlockCopy(currentK, 0, resultBuffer, offset, outputSizeBytes);
                offset += outputSizeBytes;
            }
            return resultBuffer;
        }
        catch { CryptographicOperations.ZeroMemory(resultBuffer); throw; }
        finally { CryptographicOperations.ZeroMemory(currentK); }
    }

    /// <summary>
    /// Creates the input for the pseudo-random function (PRF) by assembling the specified components such as key, fixed input,
    /// counter, and counter location based on the provided parameters.
    /// </summary>
    /// <param name="k">The key used in the PRF operation.</param>
    /// <param name="fixedInput">The fixed input data to be included in the PRF input.</param>
    /// <param name="counter">The counter value to be used if the counter is enabled.</param>
    /// <param name="counterLengthBits">The length of the counter in bits.</param>
    /// <param name="location">The location of the counter within the PRF input (e.g., before, after, or in the middle of the fixed input).</param>
    /// <param name="useCounter">Indicates whether the counter should be used in the PRF input.</param>
    /// <returns>A byte array representing the assembled PRF input.</returns>
    private static byte[] CreatePrfInput(
        byte[] k,
        byte[] fixedInput,
        uint counter,
        int counterLengthBits,
        CounterLocation location,
        bool useCounter)
    {
        using MemoryStream stream = new();
        using BinaryWriter writer = new(stream);

        if (useCounter)
        {
            byte[] counterBytes = CreateCounter(counter, counterLengthBits);

            switch (location)
            {
                case CounterLocation.BeforeFixed:
                    writer.Write(counterBytes);
                    writer.Write(k);
                    writer.Write(fixedInput);
                    break;

                case CounterLocation.AfterFixed:
                    writer.Write(k);
                    writer.Write(fixedInput);
                    writer.Write(counterBytes);
                    break;

                case CounterLocation.MiddleFixed:
                    writer.Write(k);
                    writer.Write(counterBytes);
                    writer.Write(fixedInput);
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(location), location, "Unsupported counter location");
            }
        }
        else
        {
            writer.Write(k);
            writer.Write(fixedInput);
        }

        return stream.ToArray();
    }

    /// <summary>
    /// Truncates the given result buffer to the specified length in bits.
    /// </summary>
    /// <param name="resultBuffer">The buffer containing the result data to be truncated.</param>
    /// <param name="outputLengthInBits">The desired length of the output in bits.</param>
    /// <returns>A byte array containing the truncated data according to the specified output length.</returns>
    private static byte[] TruncateToRequestedLength(byte[] resultBuffer, long outputLengthInBits)
        => BitStringUtilities.TruncateLeftmost(resultBuffer, outputLengthInBits);

    /// <summary>
    /// Creates the fixed input data used for key derivation in the feedback mode KDF.
    /// </summary>
    /// <param name="label">A label used to identify the key derivation purpose, encoded as an ASCII string.</param>
    /// <param name="context">The binary context for the key derivation, representing additional input data.</param>
    /// <param name="outputLengthInBits">The length of the key to be derived, specified in bits.</param>
    /// <returns>A byte array representing the fixed input data formatted as per the feedback mode KDF specification.</returns>
    private static byte[] CreateFixedInputData(string label, byte[] context, long outputLengthInBits)
    {
        using MemoryStream stream = new();
        using BinaryWriter writer = new(stream);

        writer.Write(KdfLabel.FromString(label).ToArray());
        writer.Write((byte)0x00);
        writer.Write(context);

        byte[] lBits = BitConverter.GetBytes((uint)outputLengthInBits);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(lBits);
        }

        writer.Write(lBits);

        return stream.ToArray();
    }

    /// <summary>
    /// Creates a counter byte array based on the provided counter value and counter length in bits.
    /// </summary>
    /// <param name="i">The counter value to be encoded as a byte array.</param>
    /// <param name="counterLengthBits">The length of the counter in bits, from 1 through 32.</param>
    /// <returns>A big-endian counter encoded in the minimum number of bytes.</returns>
    private static byte[] CreateCounter(uint i, int counterLengthBits)
        => CounterUtilities.CreateCounter(i, counterLengthBits);

    /// <summary>
    /// Asynchronously derives a key using the feedback mode key derivation function (KDF).
    /// </summary>
    /// <param name="kdk">The key derivation key (KDK) used as the cryptographic seed material.</param>
    /// <param name="label">A semantic label for the key derivation process that may contain contextual information.</param>
    /// <param name="context">A byte array containing additional context information used during key derivation.</param>
    /// <param name="outputLengthInBits">The desired output length of the derived key, in bits.</param>
    /// <param name="options">An instance of <see cref="KdfOptions"/> containing options for the key derivation process.</param>
    /// <param name="cancellationToken">A cancellation token that can be used to cancel the asynchronous operation.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains the derived key as a byte array.</returns>
    public async Task<byte[]> DeriveKeyAsync(
        byte[] kdk,
        string label,
        byte[] context,
        long outputLengthInBits,
        KdfOptions options,
        CancellationToken cancellationToken = default)
    {
        // For now, just wrap the synchronous method in a Task
        // In the future, we can add actual async operations if needed
        return await Task.Run(() => DeriveKey(kdk, label, context, outputLengthInBits, options), cancellationToken);
    }
}
