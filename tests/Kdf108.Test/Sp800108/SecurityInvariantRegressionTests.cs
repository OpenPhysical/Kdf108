// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using FluentValidation;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Kdf108.Infrastructure.Prf;

namespace Kdf108.Test.Sp800108;

[TestFixture]
[Category("Unit")]
[Parallelizable(ParallelScope.All)]
public class SecurityInvariantRegressionTests
{
    private static readonly byte[] s_key = new byte[32];
    private static readonly byte[] s_context = new byte[] { 1, 2, 3 };

    [Test]
    public void DistinctNonAsciiLabels_ProduceDistinctKeys()
    {
        CounterModeKdf kdf = new();
        KdfOptions options = CreateOptions();

        byte[] first = kdf.DeriveKey(s_key, "café", s_context, 256, options);
        byte[] second = kdf.DeriveKey(s_key, "cafñ", s_context, 256, options);

        Assert.That(second, Is.Not.EqualTo(first));
    }

    [TestCase(PrfType.CmacAes128, 15)]
    [TestCase(PrfType.CmacAes192, 16)]
    [TestCase(PrfType.CmacAes256, 24)]
    public void CmacPrfs_RejectWrongKeySize(PrfType type, int keySize)
    {
        Assert.Throws<ArgumentException>(() =>
            PrfFactory.Create(type).Compute(new byte[keySize], new byte[] { 1 }));
    }

    [Test]
    public void FixedInputEntryPoints_EnforceConfiguredOutputCap()
    {
        KdfOptions options = CreateOptions();
        options.MaxBitsAllowed = 8;

        Assert.Multiple(() =>
        {
            Assert.Throws<ValidationException>(() =>
                new CounterModeKdf().DeriveWithFixedInput(s_key, s_context, 9, options));
            Assert.Throws<ValidationException>(() =>
                new CounterModeKdf().DeriveWithSplitFixedInput(s_key, s_context, s_context, 9, options));
            Assert.Throws<ValidationException>(() =>
                new FeedbackModeKdf(true).DeriveWithFixedInput(s_key, s_context, null, 9, options));
            Assert.Throws<ValidationException>(() =>
                new DoublePipelineKdf(true).DeriveWithFixedInput(s_key, s_context, 9, options));
        });
    }

    private static KdfOptions CreateOptions() => new()
    {
        PrfType = PrfType.HmacSha256,
        CounterLengthBits = 8,
        CounterLocation = CounterLocation.BeforeFixed,
        UseCounter = true
    };
}
