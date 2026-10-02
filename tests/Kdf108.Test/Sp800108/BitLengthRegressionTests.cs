// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;

namespace Kdf108.Test.Sp800108;

[TestFixture]
[Category("Unit")]
[Parallelizable(ParallelScope.All)]
public class BitLengthRegressionTests
{
    private static readonly byte[] s_key = new byte[32];
    private static readonly byte[] s_context = new byte[] { 1, 2, 3 };

    [TestCase(1)]
    [TestCase(7)]
    [TestCase(9)]
    public void FeedbackMode_PreservesRequestedBitLength(int outputLengthInBits)
    {
        FeedbackModeKdf kdf = new(useCounter: true);

        byte[] output = kdf.DeriveKey(s_key, "label", s_context, outputLengthInBits, CreateOptions());

        AssertPartialByteOutput(output, outputLengthInBits);
    }

    [TestCase(1)]
    [TestCase(7)]
    [TestCase(9)]
    public void DoublePipelineMode_PreservesRequestedBitLength(int outputLengthInBits)
    {
        DoublePipelineKdf kdf = new(useCounter: true);

        byte[] output = kdf.DeriveKey(s_key, "label", s_context, outputLengthInBits, CreateOptions());

        AssertPartialByteOutput(output, outputLengthInBits);
    }

    [Test]
    public void NineBitCounter_DoesNotRepeatAtBlock257()
    {
        CounterModeKdf kdf = new();
        KdfOptions options = CreateOptions();
        options.CounterLengthBits = 9;
        options.MaxBitsAllowed = 257 * 256L;

        byte[] output = kdf.DeriveKey(s_key, "label", s_context, 257 * 256L, options);
        byte[] firstBlock = output[..32];
        byte[] block257 = output[(256 * 32)..(257 * 32)];

        Assert.That(block257, Is.Not.EqualTo(firstBlock));
    }

    [Test]
    public void CounterEncoding_SupportsEverySpecificationWidth()
    {
        for (int width = 1; width <= 32; width++)
        {
            uint maximum = width == 32 ? uint.MaxValue : (1u << width) - 1;
            byte[] encoded = CounterUtilities.CreateCounter(maximum, width);

            Assert.Multiple(() =>
            {
                Assert.That(encoded, Has.Length.EqualTo((width + 7) / 8), $"width {width}");
                Assert.That(ReadBigEndian(encoded), Is.EqualTo(maximum), $"width {width}");
            });
        }
    }

    private static KdfOptions CreateOptions() => new()
    {
        PrfType = PrfType.HmacSha256,
        CounterLengthBits = 8,
        CounterLocation = CounterLocation.BeforeFixed,
        UseCounter = true
    };

    private static void AssertPartialByteOutput(byte[] output, int outputLengthInBits)
    {
        int expectedBytes = (outputLengthInBits + 7) / 8;
        int unusedBits = expectedBytes * 8 - outputLengthInBits;

        Assert.Multiple(() =>
        {
            Assert.That(output, Has.Length.EqualTo(expectedBytes));
            Assert.That(output[^1] & ((1 << unusedBits) - 1), Is.Zero);
        });
    }

    private static uint ReadBigEndian(byte[] value)
    {
        uint result = 0;
        foreach (byte item in value)
        {
            result = (result << 8) | item;
        }

        return result;
    }
}
