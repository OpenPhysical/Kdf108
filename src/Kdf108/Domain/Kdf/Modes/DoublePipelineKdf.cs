// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FluentValidation;
using FluentValidation.Results;
using Kdf108.Domain.Interfaces.Kdf;
using Kdf108.Domain.Interfaces.Prf;
using Kdf108.Domain.Validator;
using Kdf108.Infrastructure.Prf;

namespace Kdf108.Domain.Kdf.Modes;

/// <summary>
/// Represents an implementation of the Double Pipeline Key Derivation Function (KDF)
/// as defined in SP 800-108 from NIST. This class supports deriving cryptographic keys
/// from a key derivation key (KDK) using a label and context as inputs.
/// </summary>
public sealed class DoublePipelineKdf : IKdf
{
    /// <summary>
    /// Validator used for validating KdfRequest instances before processing key derivation operations.
    /// </summary>
    /// <remarks>
    /// This static readonly field represents an instance of the <see cref="KdfRequestValidator"/> class
    /// and is responsible for enforcing constraints and rules on the parameters of key derivation requests
    /// in accordance with the Double Pipeline KDF mode.
    /// </remarks>
    private static readonly KdfRequestValidator s_validator = new();

    /// <summary>
    /// Indicates whether a counter should be used in the key derivation function
    /// for iteratively generating output blocks. If set to true, a counter is
    /// incorporated into the derivation logic. This provides functionality
    /// such as generating an output of a desired length by producing multiple
    /// output blocks and appending them.
    /// </summary>
    private readonly bool _useCounter;

    /// Represents a Key Derivation Function (KDF) implementing the Double Pipeline mode as defined in SP800-108 specifications.
    public DoublePipelineKdf(bool useCounter)
    {
        _useCounter = useCounter;
    }

    /// <summary>
    /// Derives a key of the specified length using the Double Pipeline Key Derivation Function.
    /// </summary>
    /// <param name="kdk">The Key Derivation Key (KDK) used for generating the derived key.</param>
    /// <param name="label">A descriptive label used as input to the key derivation process.</param>
    /// <param name="context">Contextual information that helps ensure uniqueness and integrity of the derived key.</param>
    /// <param name="outputLengthInBits">The desired length of the derived key in bits.</param>
    /// <param name="options">Additional configuration options for the key derivation function.</param>
    /// <returns>A byte array containing the derived key.</returns>
    public byte[] DeriveKey(byte[] kdk, string label, byte[] context, long outputLengthInBits, KdfOptions options) =>
        ValidateRequest(kdk, label, context, outputLengthInBits, options)
            .Bind(_ => CreateFixedInputData(label, context, outputLengthInBits))
            .Bind(fixedInput => DeriveBlocks(
                kdk,
                fixedInput,
                outputLengthInBits,
                options.PrfType,
                options.CounterLengthBits,
                options.CounterLocation,
                _useCounter
            ));

    /// <summary>
    /// Derives a key using the Double Pipeline KDF with the specified fixed input data.
    /// </summary>
    /// <param name="kdk">The key derivation key (KDK) used in the key derivation process.</param>
    /// <param name="fixedInput">The fixed input data used in the derivation process.</param>
    /// <param name="outputLengthInBits">The desired length of the output key in bits.</param>
    /// <param name="options">The configuration options for the KDF, specifying parameters like PRF type, counter length, and counter location.</param>
    /// <returns>A byte array containing the derived key with the specified output length.</returns>
    public byte[] DeriveWithFixedInput(byte[] kdk, byte[] fixedInput, long outputLengthInBits, KdfOptions options)
    {
        KdfInputValidator.ValidateFixedInput(kdk, fixedInput, outputLengthInBits, options);
        return DeriveBlocks(
            kdk,
            fixedInput,
            outputLengthInBits,
            options.PrfType,
            options.CounterLengthBits,
            options.CounterLocation,
            _useCounter);
    }

    /// <summary>
    /// Validates the provided key derivation request parameters and returns a populated <see cref="KdfRequest"/> object.
    /// Throws a <see cref="ValidationException"/> if the request parameters are invalid.
    /// </summary>
    /// <param name="kdk">The key derivation key used as the base for the Key Derivation Function (KDF).</param>
    /// <param name="label">A string label that provides context for the generated key.</param>
    /// <param name="context">A byte array representing additional contextual information used in the key derivation process.</param>
    /// <param name="outputLengthInBits">The desired output key length in bits.</param>
    /// <param name="options">Additional key derivation options, such as the PRF type, counter settings, and counter location.</param>
    /// <returns>An instance of <see cref="KdfRequest"/> that encapsulates the provided key derivation parameters.</returns>
    /// <exception cref="ValidationException">Thrown when the provided parameters fail validation.</exception>
    private static KdfRequest ValidateRequest(byte[] kdk, string label, byte[] context, long outputLengthInBits,
        KdfOptions options)
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
    /// Derives key blocks based on the given inputs and configurations using a specified pseudorandom function (PRF).
    /// </summary>
    /// <param name="kdk">The key derivation key (KDK) used as an input for the PRF.</param>
    /// <param name="fixedInput">The fixed input data used for key derivation.</param>
    /// <param name="outputLengthInBits">The desired output length in bits.</param>
    /// <param name="prfType">The type of PRF to use for key derivation, such as HMAC or CMAC variants.</param>
    /// <param name="counterLengthBits">The length of the counter in bits.</param>
    /// <param name="counterLocation">The location of the counter relative to the fixed input (before, after, or middle).</param>
    /// <param name="useCounter">A value indicating whether the counter should be included in the derivation process.</param>
    /// <returns>A byte array representing the derived key material truncated to the requested length.</returns>
    private static byte[] DeriveBlocks(
        byte[] kdk,
        byte[] fixedInput,
        long outputLengthInBits,
        PrfType prfType,
        int counterLengthBits,
        CounterLocation counterLocation,
        bool useCounter)
    {
        IPrf prf = PrfFactory.Create(prfType);
        int outputSizeBits = prf.OutputSizeBits;
        int outputSizeBytes = outputSizeBits / 8;
        long reps = (long)Math.Ceiling(outputLengthInBits / (double)outputSizeBits);

        ValidateCounterAndOutputSize(reps, counterLengthBits, outputLengthInBits, useCounter);

        // First pipeline: Generate A values
        IReadOnlyList<byte[]> aValues = GenerateAValues(kdk, prf, fixedInput, reps);

        // Second pipeline: Generate K values and combine them
        byte[] resultBuffer = GenerateKValues(
            kdk,
            prf,
            fixedInput,
            aValues,
            reps,
            outputSizeBytes,
            counterLengthBits,
            counterLocation,
            useCounter
        );

        // Truncate to requested length
        return TruncateToRequestedLength(resultBuffer, outputLengthInBits);
    }

    /// <summary>
    /// Validates the counter value and output size for the key derivation process.
    /// </summary>
    /// <param name="reps">The number of iterations or blocks required to derive the key.</param>
    /// <param name="counterLengthBits">The length of the counter in bits.</param>
    /// <param name="outputLengthInBits">The desired output length in bits.</param>
    /// <param name="useCounter">Specifies whether a counter is used in the key derivation process.</param>
    /// <exception cref="ArgumentException">
    /// Thrown if the output length exceeds the counter's maximum limit or the buffer size constraints of the platform.
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
    /// Generates a sequence of intermediate values (A values) used in double-pipeline key derivation function calculations.
    /// </summary>
    /// <param name="kdk">The Key Derivation Key (KDK) used as input to the pseudorandom function.</param>
    /// <param name="prf">The pseudorandom function (PRF) to compute values.</param>
    /// <param name="fixedInput">The fixed input data used to initialize the process.</param>
    /// <param name="reps">The total number of computations to perform, corresponding to the required output size.</param>
    /// <returns>A read-only list of byte arrays containing the generated A values.</returns>
    private static IReadOnlyList<byte[]> GenerateAValues(byte[] kdk, IPrf prf, byte[] fixedInput, long reps)
    {
        List<byte[]> aValues = new((int)reps + 1) { fixedInput };

        for (int i = 1; i <= reps; i++)
        {
            aValues.Add(prf.Compute(kdk, aValues[i - 1]));
        }

        return aValues;
    }

    /// <summary>
    /// Generates the K values required as part of the key derivation process using a double pipeline KDF.
    /// This method performs computations to produce intermediate blocks that are then combined into the derived key.
    /// </summary>
    /// <param name="kdk">The key derivation key (KDK) used as the basis for the derived key.</param>
    /// <param name="prf">The pseudo-random function (PRF) implementation used in the key derivation process.</param>
    /// <param name="fixedInput">The fixed input data used in the key derivation operation.</param>
    /// <param name="aValues">The sequence of intermediate A values generated from the first pipeline computation.</param>
    /// <param name="reps">The total number of PRF iterations needed to generate the required length of output key material.</param>
    /// <param name="outputSizeBytes">The size of the PRF output in bytes.</param>
    /// <param name="counterLengthBits">The length of the counter in bits, which is used to ensure uniqueness across iterations in the PRF input.</param>
    /// <param name="counterLocation">The position of the counter (e.g., before, after, or within the fixed input) in the PRF input.</param>
    /// <param name="useCounter">Indicates whether a counter is used in the key derivation process.</param>
    /// <returns>A byte array containing the calculated K values, concatenated and optionally truncated to the requested output length.</returns>
    private static byte[] GenerateKValues(
        byte[] kdk,
        IPrf prf,
        byte[] fixedInput,
        IReadOnlyList<byte[]> aValues,
        long reps,
        int outputSizeBytes,
        int counterLengthBits,
        CounterLocation counterLocation,
        bool useCounter)
    {
        byte[] resultBuffer = new byte[reps * outputSizeBytes];
        int offset = 0;

        for (uint i = 1; i <= reps; i++)
        {
            byte[] prfInput = CreatePrfInput(
                aValues[(int)i],
                fixedInput,
                i,
                counterLengthBits,
                counterLocation,
                useCounter
            );

            byte[] block = prf.Compute(kdk, prfInput);

            Buffer.BlockCopy(block, 0, resultBuffer, offset, outputSizeBytes);
            offset += outputSizeBytes;
        }

        return resultBuffer;
    }

    /// <summary>
    /// Creates the input data for the pseudo-random function (PRF) based on the provided parameters.
    /// </summary>
    /// <param name="aValue">The intermediate value (A(i)) generated during key derivation.</param>
    /// <param name="fixedInput">The fixed input portion for the key derivation process.</param>
    /// <param name="counter">The counter value used in the key derivation process.</param>
    /// <param name="counterLengthBits">The length of the counter in bits.</param>
    /// <param name="location">The location of the counter relative to the fixed input (e.g., before, after, or in the middle).</param>
    /// <param name="useCounter">Indicates whether to include the counter in the PRF input.</param>
    /// <returns>A byte array representing the constructed input data for the PRF.</returns>
    private static byte[] CreatePrfInput(
        byte[] aValue,
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
                    writer.Write(aValue);
                    writer.Write(fixedInput);
                    break;

                case CounterLocation.AfterFixed:
                    writer.Write(aValue);
                    writer.Write(fixedInput);
                    writer.Write(counterBytes);
                    break;

                case CounterLocation.MiddleFixed:
                    writer.Write(aValue);
                    writer.Write(counterBytes);
                    writer.Write(fixedInput);
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(location), location, "Unsupported counter location");
            }
        }
        else
        {
            writer.Write(aValue);
            writer.Write(fixedInput);
        }

        return stream.ToArray();
    }

    /// <summary>
    /// Truncates the generated key material to the requested output length in bits.
    /// </summary>
    /// <param name="resultBuffer">
    /// The source buffer containing the derived key material to be truncated.
    /// </param>
    /// <param name="outputLengthInBits">
    /// The desired length of the output key material in bits.
    /// </param>
    /// <returns>
    /// A byte array containing the truncated key material with the specified length.
    /// </returns>
    private static byte[] TruncateToRequestedLength(byte[] resultBuffer, long outputLengthInBits)
        => BitStringUtilities.TruncateLeftmost(resultBuffer, outputLengthInBits);

    /// <summary>
    /// Creates the fixed input data as required by the KDF mechanism, which combines the label, context, and output length in bits.
    /// </summary>
    /// <param name="label">The label string to include in the fixed input data.</param>
    /// <param name="context">The context byte array to include in the fixed input data.</param>
    /// <param name="outputLengthInBits">The desired output length in bits to include in the fixed input data.</param>
    /// <returns>Returns a byte array representing the fixed input data.</returns>
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
    /// Creates a byte array representation of a counter value with the specified bit length.
    /// </summary>
    /// <param name="i">The integer value of the counter to convert.</param>
    /// <param name="counterLengthBits">The length of the counter in bits.</param>
    /// <returns>A byte array representing the counter value.</returns>
    private static byte[] CreateCounter(uint i, int counterLengthBits)
        => CounterUtilities.CreateCounter(i, counterLengthBits);

    /// <summary>
    /// Derives a cryptographic key based on the provided parameters, using the Double-Pipeline KDF mode.
    /// </summary>
    /// <param name="kdk">The key derivation key (KDK) used as input to the KDF.</param>
    /// <param name="label">A string label used to provide context for the derived key.</param>
    /// <param name="context">An optional byte array representing additional context information, such as a unique identifier.</param>
    /// <param name="outputLengthInBits">The desired length of the derived key in bits.</param>
    /// <param name="options">Additional KDF options or parameters.</param>
    /// <param name="cancellationToken">A cancellation token to observe while waiting for the operation to complete.</param>
    /// <returns>A task representing the asynchronous operation, which returns the derived key as a byte array.</returns>
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
