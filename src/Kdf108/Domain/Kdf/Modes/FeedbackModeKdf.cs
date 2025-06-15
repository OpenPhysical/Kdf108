// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System;
using System.IO;
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

public sealed class FeedbackModeKdf : IKdf
{
    private static readonly KdfRequestValidator s_validator = new();
    private readonly bool _useCounter;

    public FeedbackModeKdf(bool useCounter) => _useCounter = useCounter;

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

    public byte[] DeriveWithFixedInput(byte[] kdk, byte[] fixedInput, byte[]? iv, long outputLengthInBits,
        KdfOptions options) =>
        DeriveBlocks(
            kdk,
            fixedInput,
            iv ?? new byte[0],
            outputLengthInBits,
            options.PrfType,
            options.CounterLengthBits,
            options.CounterLocation,
            _useCounter
        );

    private KdfRequest ValidateRequest(byte[] kdk, string label, byte[] context, long outputLengthInBits,
        KdfOptions options)
    {
        KdfRequest? request = new(
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

        long reps = (long)Math.Ceiling(outputLengthInBits / (double)outputSizeBits);

        ValidateCounterAndOutputSize(reps, counterLengthBits, outputLengthInBits, useCounter);

        return GenerateBlocks(kdk, fixedInput, iv, reps, prf, outputSizeBytes, counterLengthBits, counterLocation,
                useCounter)
            .Pipe(resultBuffer => TruncateToRequestedLength(resultBuffer, outputLengthInBits));
    }

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
        byte[] resultBuffer = new byte[reps * outputSizeBytes];
        int offset = 0;
        byte[] currentK = iv;

        for (uint i = 1; i <= reps; i++)
        {
            byte[] prfInput = CreatePrfInput(currentK, fixedInput, i, counterLengthBits, counterLocation, useCounter);
            currentK = prf.Compute(kdk, prfInput);

            Buffer.BlockCopy(currentK, 0, resultBuffer, offset, outputSizeBytes);
            offset += outputSizeBytes;
        }

        return resultBuffer;
    }

    private static byte[] CreatePrfInput(
        byte[] k,
        byte[] fixedInput,
        uint counter,
        int counterLengthBits,
        CounterLocation location,
        bool useCounter)
    {
        using MemoryStream? stream = new();
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

    private static byte[] TruncateToRequestedLength(byte[] resultBuffer, long outputLengthInBits)
    {
        int finalBytes = (int)(outputLengthInBits / 8);
        byte[] output = new byte[finalBytes];
        Buffer.BlockCopy(resultBuffer, 0, output, 0, finalBytes);
        return output;
    }

    private static byte[] CreateFixedInputData(string label, byte[] context, long outputLengthInBits)
    {
        using MemoryStream? stream = new();
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
