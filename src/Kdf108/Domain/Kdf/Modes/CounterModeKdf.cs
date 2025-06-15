// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using FluentValidation;
using FluentValidation.Results;
using Kdf108.Domain.Interfaces.Kdf;
using Kdf108.Domain.Interfaces.Prf;
using Kdf108.Domain.Validator;
using Kdf108.Infrastructure.Prf;
using Kdf108.Internal;

#endregion

namespace Kdf108.Domain.Kdf.Modes;

public sealed class CounterModeKdf : IKdf
{
    private static readonly KdfRequestValidator s_validator = new();

    public byte[] DeriveKey(byte[] kdk, string label, byte[] context, long outputLengthInBits, KdfOptions options) =>
        CreateAndValidateRequest(kdk, label, context, outputLengthInBits, options)
            .Bind(request => CreateFixedInputData(label, context, outputLengthInBits))
            .Bind(fixedInput => DeriveBlocks(
                kdk,
                outputLengthInBits,
                fixedInput,
                options.PrfType,
                options.CounterLocation,
                options.CounterLengthBits
            ));

    public byte[] DeriveWithFixedInput(byte[] kdk, byte[] fixedInput, long outputLengthInBits, KdfOptions options) =>
        DeriveBlocks(
            kdk,
            outputLengthInBits,
            fixedInput,
            options.PrfType,
            options.CounterLocation,
            options.CounterLengthBits
        );

    public byte[] DeriveWithSplitFixedInput(byte[] kdk, byte[] dataBeforeCounter, byte[] dataAfterCounter,
        long outputLengthInBits, KdfOptions options)
    {
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

                if (i == 1)
                {
                    Console.WriteLine("PRF INPUT (block 1): " + ConvertCompat.ToHexString(prfInput));
                    Console.WriteLine("PRF OUTPUT (block 1): " + ConvertCompat.ToHexString(block));
                }

                return block;
            });
    }

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

    private static byte[] CreateSplitInputBlock(byte[] kdk, IPrf prf, byte[] before, byte[] counter, byte[] after)
    {
        using MemoryStream stream = new();
        using BinaryWriter writer = new(stream);

        writer.Write(before);
        writer.Write(counter);
        writer.Write(after);

        return prf.Compute(kdk, stream.ToArray());
    }

    private static byte[] TruncateToRequestedLength(
        IEnumerable<byte[]> blocks,
        long outputLengthInBits,
        int outputSizeBytes)
    {
        // Defensive: ensure all blocks are of expected size
        List<byte> flattened = new();

        foreach (byte[]? block in blocks)
        {
            if (block.Length != outputSizeBytes)
            {
                throw new InvalidOperationException(
                    $"PRF block length {block.Length} does not match expected {outputSizeBytes} bytes.");
            }

            flattened.AddRange(block);
        }

        int fullBytes = (int)(outputLengthInBits / 8);
        int extraBits = (int)(outputLengthInBits % 8);
        int totalBytes = fullBytes + (extraBits > 0 ? 1 : 0);

        if (flattened.Count < totalBytes)
        {
            throw new InvalidOperationException("Insufficient PRF output to satisfy requested bit-length.");
        }

        byte[] output = new byte[totalBytes];
        flattened.CopyTo(0, output, 0, totalBytes);

        if (extraBits <= 0)
        {
            return output;
        }

        int mask = 0xFF << (8 - extraBits);
        output[fullBytes] &= (byte)mask;

        return output;
    }


    private static byte[] CreateFixedInputData(string label, byte[] context, long outputLengthInBits)
    {
        using MemoryStream stream = new();
        using BinaryWriter writer = new(stream);

        writer.Write(Encoding.ASCII.GetBytes(label));
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

    private static byte[] CreateCounter(uint i, int counterLengthBits)
    {
        int bytes = counterLengthBits / 8;
        byte[] counter = new byte[bytes];

        for (int j = bytes - 1, shift = 0; j >= 0; j--, shift += 8)
        {
            counter[j] = (byte)((i >> shift) & 0xFF);
        }

        return counter;
    }
}
