// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
/// Provides an implementation of a counter-mode key derivation function (KDF).
/// The CounterModeKdf allows deriving cryptographic keys of a specified length
/// from a given key derivation key (KDK), using a specific key derivation function (PRF)
/// and customizable parameters such as labels, context, counter configuration, and more.
/// </summary>
public sealed class CounterModeKdf : IKdf
{
    /// <summary>
    /// A static readonly instance of the <see cref="KdfRequestValidator"/> class.
    /// Used to validate instances of <see cref="KdfRequest"/> for correctness and integrity before processing.
    /// </summary>
    private static readonly KdfRequestValidator s_validator = new();

    private readonly ILogger<CounterModeKdf> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="CounterModeKdf"/> class.
    /// </summary>
    /// <param name="logger">The logger instance for logging operations. If null, NullLogger is used.</param>
    public CounterModeKdf(ILogger<CounterModeKdf>? logger = null)
    {
        _logger = logger ?? NullLogger<CounterModeKdf>.Instance;
    }

    /// <summary>
    /// Derives a cryptographic key using the Counter Mode Key Derivation Function (KDF).
    /// </summary>
    /// <param name="kdk">The key derivation key (KDK) used as the base key material for deriving the resulting key.</param>
    /// <param name="label">A label that provides additional context or domain separation during key derivation.</param>
    /// <param name="context">A context value that provides additional input for diversification of the derived key.</param>
    /// <param name="outputLengthInBits">The desired length of the derived key, specified in bits.</param>
    /// <param name="options">Options for configuring the KDF, including pseudo-random function type, counter location, and counter length.</param>
    /// <returns>A byte array containing the derived key material.</returns>
    public byte[] DeriveKey(byte[] kdk, string label, byte[] context, long outputLengthInBits, KdfOptions options)
    {
        _logger.LogDebug("Starting Counter Mode KDF derivation. Label: {Label}, OutputLength: {OutputLengthBits} bits, PRF: {PrfType}", 
            label, outputLengthInBits, options.PrfType);
        
        try
        {
            var result = CreateAndValidateRequest(kdk, label, context, outputLengthInBits, options)
                .Bind(request => CreateFixedInputData(label, context, outputLengthInBits))
                .Bind(fixedInput => DeriveBlocks(
                    kdk,
                    outputLengthInBits,
                    fixedInput,
                    options.PrfType,
                    options.CounterLocation,
                    options.CounterLengthBits
                ));

            _logger.LogInformation("Successfully derived key using Counter Mode KDF. OutputLength: {OutputLengthBits} bits", outputLengthInBits);
            return result;
        }
        catch (ValidationException ex)
        {
            _logger.LogError(ex, "Validation failed during Counter Mode KDF derivation");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during Counter Mode KDF derivation");
            throw;
        }
    }

    /// <summary>
    /// Derives a key using the provided key derivation key (KDK) and fixed input data
    /// according to the Counter Mode KDF specification.
    /// </summary>
    /// <param name="kdk">
    /// The key derivation key (KDK) to be used in the key derivation process.
    /// </param>
    /// <param name="fixedInput">
    /// The fixed input data to be used during key derivation.
    /// </param>
    /// <param name="outputLengthInBits">
    /// The desired length of the derived key, specified in bits.
    /// </param>
    /// <param name="options">
    /// Configuration options for the key derivation process, including PRF type, counter location, and counter length.
    /// </param>
    /// <returns>
    /// A byte array containing the derived key of the specified length.
    /// </returns>
    public byte[] DeriveWithFixedInput(byte[] kdk, byte[] fixedInput, long outputLengthInBits, KdfOptions options)
    {
        KdfInputValidator.ValidateFixedInput(kdk, fixedInput, outputLengthInBits, options);
        return DeriveBlocks(
            kdk,
            outputLengthInBits,
            fixedInput,
            options.PrfType,
            options.CounterLocation,
            options.CounterLengthBits);
    }

    /// Derives key material using the Counter Mode Key Derivation Function (KDF)
    /// with a split fixed input format, a counter, and specified KDF options.
    /// The method generates an output key of the specified length by combining
    /// the provided key derivation key (KDK), fixed inputs (before and after the counter),
    /// and a pseudo-random function (PRF) determined by the KdfOptions provided.
    /// <param name="kdk">The key derivation key (KDK) used as the base for the KDF.</param>
    /// <param name="dataBeforeCounter">The fixed input data that appears before the counter in the input string.</param>
    /// <param name="dataAfterCounter">The fixed input data that appears after the counter in the input string.</param>
    /// <param name="outputLengthInBits">The desired length of the output key material, in bits.</param>
    /// <param name="options">The configuration options for the KDF, including the selected PRF and counter settings.</param>
    /// <returns>A byte array representing the derived key material of the specified length.</returns>
    public byte[] DeriveWithSplitFixedInput(byte[] kdk, byte[] dataBeforeCounter, byte[] dataAfterCounter,
        long outputLengthInBits, KdfOptions options)
    {
        KdfInputValidator.ValidateFixedInput(kdk, dataAfterCounter, outputLengthInBits, options);
        ArgumentNullException.ThrowIfNull(dataBeforeCounter);
        IPrf prf = PrfFactory.Create(options.PrfType);
        return DeriveBlocksWithSplitInput(
            kdk,
            outputLengthInBits,
            dataBeforeCounter,
            dataAfterCounter,
            prf,
            options.CounterLengthBits
        );
    }

    /// <summary>
    /// Creates a <see cref="KdfRequest"/> object based on the provided parameters and validates it.
    /// If the validation fails, a <see cref="ValidationException"/> is thrown.
    /// </summary>
    /// <param name="kdk">The key derivation key (KDK) used as the basis for the key derivation process.</param>
    /// <param name="label">A string label used in the derivation process, providing additional context.</param>
    /// <param name="context">A byte array representing contextual information for the derivation process.</param>
    /// <param name="outputLengthInBits">The desired output key length in bits.</param>
    /// <param name="options">Configuration options for the key derivation process.</param>
    /// <returns>A valid <see cref="KdfRequest"/> object if validation succeeds.</returns>
    /// <exception cref="ValidationException">Thrown if the provided input parameters fail the validation rules.</exception>
    private static KdfRequest CreateAndValidateRequest(
        byte[] kdk, string label, byte[] context, long outputLengthInBits, KdfOptions options)
    {
        KdfRequest request = new(kdk,
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
    /// Derives cryptographic blocks based on a key derivation key (KDK), fixed input,
    /// and various parameters using a pseudo-random function (PRF).
    /// </summary>
    /// <param name="kdk">The key derivation key used as the initial keying material.</param>
    /// <param name="outputLengthInBits">The desired output length in bits for the derived key material.</param>
    /// <param name="fixedInput">The fixed input data used for block derivation.</param>
    /// <param name="prfType">The type of pseudo-random function (PRF) used during key derivation.</param>
    /// <param name="counterLocation">The location of the counter within the fixed input data (before, after, or middle).</param>
    /// <param name="counterLengthBits">The length of the counter in bits used within the derivation process.</param>
    /// <returns>A byte array containing the derived key material truncated to the requested output length.</returns>
    private static byte[] DeriveBlocks(
        byte[] kdk,
        long outputLengthInBits,
        byte[] fixedInput,
        PrfType prfType,
        CounterLocation counterLocation,
        int counterLengthBits)
    {
        IPrf prf = PrfFactory.Create(prfType);
        int outputSizeBits = prf.OutputSizeBits;
        int outputSizeBytes = outputSizeBits / 8;

        long reps = (long)Math.Ceiling(outputLengthInBits / (double)outputSizeBits);
        ValidateCounterSizeLimit(reps, counterLengthBits, outputLengthInBits);

        return GenerateBlocks(kdk, reps, fixedInput, prf, counterLocation, counterLengthBits)
            .Pipe(blocks => TruncateToRequestedLength(blocks, outputLengthInBits, outputSizeBytes));
    }

    /// <summary>
    /// Validates whether the requested output length and repetitions fit within the counter size limit.
    /// </summary>
    /// <param name="reps">The number of iterations required to produce the desired output length in bits.</param>
    /// <param name="counterLengthBits">The length of the counter in bits.</param>
    /// <param name="outputLengthInBits">The requested output length in bits.</param>
    /// <exception cref="ArgumentException">
    /// Thrown when the number of iterations exceeds the maximum value defined by the counter size.
    /// </exception>
    private static void ValidateCounterSizeLimit(long reps, int counterLengthBits, long outputLengthInBits)
    {
        long maxCounter = (1L << counterLengthBits) - 1;
        if (reps > maxCounter)
        {
            throw new ArgumentException(
                $"Too much output requested — exceeds counter limit (2^{counterLengthBits} blocks).",
                nameof(outputLengthInBits));
        }
    }

    /// <summary>
    /// Generates a sequence of cryptographic blocks using a key derivation function (KDF) and
    /// specified inputs and parameters.
    /// </summary>
    /// <param name="kdk">The key derivation key used by the pseudorandom function (PRF).</param>
    /// <param name="reps">The number of blocks to generate, determined by the output length.</param>
    /// <param name="fixedInput">A fixed input byte array that provides context for the PRF calculation.</param>
    /// <param name="prf">The pseudorandom function implementation used for key derivation.</param>
    /// <param name="counterLocation">Specifies the location of the counter in the PRF input block.</param>
    /// <param name="counterLengthBits">The size of the counter in bits, dictating how many iterations are supported.</param>
    /// <returns>A collection of byte arrays, each representing a cryptographic block derived from the inputs.</returns>
    private static IEnumerable<byte[]> GenerateBlocks(
        byte[] kdk,
        long reps,
        byte[] fixedInput,
        IPrf prf,
        CounterLocation counterLocation,
        int counterLengthBits)
    {
        return Enumerable.Range(1, (int)reps)
            .Select(i =>
            {
                uint counter = (uint)i;
                byte[] prfInput = CreatePrfInput(
                    CreateCounter(counter, counterLengthBits),
                    fixedInput,
                    counterLocation,
                    null
                );

                byte[] block = prf.Compute(kdk, prfInput);

                return block;
            });
    }

    /// <summary>
    /// Constructs the input data for the Pseudo-Random Function (PRF) based on the provided counter, fixed input data,
    /// counter location, and optional key control mitigation.
    /// </summary>
    /// <param name="counter">
    /// The counter value to be included in the PRF input. The placement depends on the specified counter location.
    /// </param>
    /// <param name="fixedInput">
    /// The fixed input data to be combined with the counter to form the PRF input. This data remains constant during key derivation.
    /// </param>
    /// <param name="location">
    /// The location of the counter in relation to the fixed input. This can be either before, after, or middle of the fixed input.
    /// </param>
    /// <param name="keyControlMitigation">
    /// Optional data to be appended to the PRF input for additional key control mitigation. Can be null if not required.
    /// </param>
    /// <returns>
    /// Returns a byte array representing the constructed PRF input data based on the provided parameters.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when an unsupported or invalid counter location is specified.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the middle counter location is requested, as it requires the use of another method.
    /// </exception>
    private static byte[] CreatePrfInput(
        byte[] counter,
        byte[] fixedInput,
        CounterLocation location,
        byte[]? keyControlMitigation)
    {
        using MemoryStream stream = new();
        using BinaryWriter writer = new(stream);

        switch (location)
        {
            case CounterLocation.BeforeFixed:
                writer.Write(counter);
                writer.Write(fixedInput);
                if (keyControlMitigation != null)
                {
                    writer.Write(keyControlMitigation);
                }

                break;

            case CounterLocation.AfterFixed:
                writer.Write(fixedInput);
                if (keyControlMitigation != null)
                {
                    writer.Write(keyControlMitigation);
                }

                writer.Write(counter);
                break;

            case CounterLocation.MiddleFixed:
                throw new InvalidOperationException(
                    "Middle counter location requires using DeriveWithSplitFixedInput method");

            default:
                throw new ArgumentOutOfRangeException(nameof(location), location, "Unsupported counter location");
        }

        return stream.ToArray();
    }

    /// <summary>
    /// Derives cryptographic key material using a counter mode KDF and a split input structure, which separates
    /// the input data into sections before and after a counter value.
    /// </summary>
    /// <param name="kdk">The key derivation key (kdk) used as the basis for generating derived keys.</param>
    /// <param name="outputLengthInBits">The required length of the output in bits.</param>
    /// <param name="dataBeforeCounter">The portion of the fixed input data that comes before the counter.</param>
    /// <param name="dataAfterCounter">The portion of the fixed input data that comes after the counter.</param>
    /// <param name="prf">The pseudorandom function (PRF) used in the derivation process.</param>
    /// <param name="counterLengthBits">The length of the counter in bits, used to iterate through the derivation process.</param>
    /// <returns>A byte array containing the derived cryptographic key material.</returns>
    private static byte[] DeriveBlocksWithSplitInput(
        byte[] kdk,
        long outputLengthInBits,
        byte[] dataBeforeCounter,
        byte[] dataAfterCounter,
        IPrf prf,
        int counterLengthBits)
    {
        int outputSizeBits = prf.OutputSizeBits;
        int outputSizeBytes = outputSizeBits / 8;

        long reps = (long)Math.Ceiling(outputLengthInBits / (double)outputSizeBits);
        ValidateCounterSizeLimit(reps, counterLengthBits, outputLengthInBits);

        List<byte[]> blocks = Enumerable.Range(1, (int)reps)
            .Select(i => CreateSplitInputBlock(kdk, prf, dataBeforeCounter, CreateCounter((uint)i, counterLengthBits),
                dataAfterCounter))
            .ToList();

        return TruncateToRequestedLength(blocks, outputLengthInBits, outputSizeBytes);
    }

    /// <summary>
    /// Creates a split input block by combining the specified components (before the counter, the counter, and after the counter),
    /// and then computing the pseudorandom function (PRF) over the resulting data using the provided key derivation key (KDK).
    /// </summary>
    /// <param name="kdk">The key derivation key used by the pseudorandom function.</param>
    /// <param name="prf">The pseudorandom function used to compute the output block.</param>
    /// <param name="before">The portion of the data that comes before the counter.</param>
    /// <param name="counter">The counter value to be inserted between the data portions.</param>
    /// <param name="after">The portion of the data that comes after the counter.</param>
    /// <returns>The resulting split input block as a byte array after computation by the pseudorandom function.</returns>
    private static byte[] CreateSplitInputBlock(byte[] kdk, IPrf prf, byte[] before, byte[] counter, byte[] after)
    {
        using MemoryStream stream = new();
        using BinaryWriter writer = new(stream);

        writer.Write(before);
        writer.Write(counter);
        writer.Write(after);

        return prf.Compute(kdk, stream.ToArray());
    }

    /// <summary>
    /// Truncates the provided blocks of bytes to match the requested output length in bits.
    /// Ensures that the output is of the desired total byte length and applies bit masking
    /// if the requested output length includes partial bits.
    /// </summary>
    /// <param name="blocks">A collection of PRF output blocks represented as byte arrays.</param>
    /// <param name="outputLengthInBits">The desired output length in bits.</param>
    /// <param name="outputSizeBytes">The expected size of each block in bytes, as determined by the PRF output.</param>
    /// <returns>A byte array containing the truncated output data, with the specified bit length.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if any block does not match the expected block size or if the total
    /// PRF output size is insufficient to satisfy the requested length.
    /// </exception>
    private static byte[] TruncateToRequestedLength(
        IEnumerable<byte[]> blocks,
        long outputLengthInBits,
        int outputSizeBytes)
    {
        // Defensive: ensure all blocks are of expected size
        List<byte> flattened = new();

        foreach (byte[] block in blocks)
        {
            if (block.Length != outputSizeBytes)
            {
                throw new InvalidOperationException(
                    $"PRF block length {block.Length} does not match expected {outputSizeBytes} bytes.");
            }

            flattened.AddRange(block);
        }

        return BitStringUtilities.TruncateLeftmost(flattened.ToArray(), outputLengthInBits);
    }


    /// <summary>
    /// Constructs a fixed input data message for use in the Counter Mode Key Derivation Function (KDF).
    /// The fixed input data is generated by concatenating the label, a null byte, the context, and the output length in bits.
    /// </summary>
    /// <param name="label">A string label used for identifying the key derivation purpose, converted to ASCII encoding.</param>
    /// <param name="context">A byte array providing additional information specific to the key derivation context.</param>
    /// <param name="outputLengthInBits">The desired output length in bits for the derived key material.</param>
    /// <returns>A byte array representing the constructed fixed input data.</returns>
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
    /// Creates a counter value encoded as a byte array with the specified length in bits.
    /// </summary>
    /// <param name="i">The counter value to be encoded.</param>
    /// <param name="counterLengthBits">The length of the counter in bits, from 1 through 32.</param>
    /// <returns>A big-endian counter encoded in the minimum number of bytes.</returns>
    private static byte[] CreateCounter(uint i, int counterLengthBits)
        => CounterUtilities.CreateCounter(i, counterLengthBits);

    /// <inheritdoc/>
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
