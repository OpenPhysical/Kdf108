// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using AwesomeAssertions;
using FluentValidation;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;

namespace Kdf108.Test.Sp800108;

[TestFixture]
public class OutputLimitTests
{
    [TestCase(8)]
    [TestCase(4294967296L)]
    public void CounterMode_RejectsLengthsBeyondOneBitCounterOrLField(long bits)
    {
        var options = new KdfOptions
        {
            PrfType = PrfType.HmacSha256,
            CounterLengthBits = 1,
            MaxBitsAllowed = long.MaxValue
        };

        Action derive = () => new CounterModeKdf().DeriveWithFixedInput(
            new byte[32], Array.Empty<byte>(), bits, options);

        if (bits == 8)
            derive.Should().NotThrow();
        else
            derive.Should().Throw<ValidationException>();
    }

    [Test]
    public void CounterMode_RejectsOutputExceedingCounterBeforePrfWork()
    {
        var options = new KdfOptions
        {
            PrfType = PrfType.HmacSha256,
            CounterLengthBits = 1,
            MaxBitsAllowed = 1024
        };

        Action derive = () => new CounterModeKdf().DeriveWithFixedInput(
            new byte[32], Array.Empty<byte>(), 513, options);

        derive.Should().Throw<ArgumentException>().WithMessage("*counter limit*");
    }
}
