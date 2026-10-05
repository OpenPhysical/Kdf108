// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Sp800108;
using Kdf108.Infrastructure.Prf;

namespace Kdf108.Test.Sp800108;

[TestFixture]
[Category("Unit")]
[Category("Conformance")]
public sealed class Sp800108KmacTests
{
    // NIST SP 800-185, Appendix A, KMAC Sample #1. SP 800-108 maps X to Context and S to Label.
    [Test]
    public void Kmac128_MatchesNistSp800185Sample1()
    {
        byte[] key = Convert.FromHexString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
        byte[] context = Convert.FromHexString("00010203");
        byte[] expected = Convert.FromHexString("E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E");

        byte[] actual = Sp800108Kmac.DeriveKey(key, context, 256);

        Assert.That(actual, Is.EqualTo(expected));
    }

    [Test]
    public void Label_IsKmacCustomizationString()
    {
        byte[] key = Convert.FromHexString("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
        byte[] context = Convert.FromHexString("00010203");

        byte[] withoutLabel = Sp800108Kmac.DeriveKey(key, context, 256);
        byte[] withLabel = Sp800108Kmac.DeriveKey(key, context, 256, label: "KDF"u8);

        Assert.That(withLabel, Is.Not.EqualTo(withoutLabel));
    }

    [TestCase(0)]
    [TestCase(-8)]
    [TestCase(8200)]
    public void RejectsInvalidOrExcessiveOutputLength(int outputLengthBits) =>
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            Sp800108Kmac.DeriveKey(new byte[32], ReadOnlySpan<byte>.Empty, outputLengthBits));

    [Test]
    public void RejectsNonOctetAlignedOutputLength() =>
        Assert.Throws<ArgumentException>(() =>
            Sp800108Kmac.DeriveKey(new byte[32], ReadOnlySpan<byte>.Empty, 255));

    [TestCase(Sp800108KmacAlgorithm.Kmac128, 15)]
    [TestCase(Sp800108KmacAlgorithm.Kmac256, 31)]
    public void RejectsKeyBelowAlgorithmStrength(Sp800108KmacAlgorithm algorithm, int keyBytes) =>
        Assert.Throws<ArgumentException>(() =>
            Sp800108Kmac.DeriveKey(new byte[keyBytes], ReadOnlySpan<byte>.Empty, 256, algorithm));

    [Test]
    public void PublicPrfPolicyContainsOnlyApprovedAlgorithms()
    {
        PrfType[] approved =
        [
            PrfType.HmacSha1,
            PrfType.HmacSha224,
            PrfType.HmacSha256,
            PrfType.HmacSha384,
            PrfType.HmacSha512,
            PrfType.HmacSha512_224,
            PrfType.HmacSha512_256,
            PrfType.HmacSha3_224,
            PrfType.HmacSha3_256,
            PrfType.HmacSha3_384,
            PrfType.HmacSha3_512,
            PrfType.CmacAes128,
            PrfType.CmacAes192,
            PrfType.CmacAes256
        ];

        Assert.That(Enum.GetValues<PrfType>(), Is.EqualTo(approved));
        Assert.Multiple(() =>
        {
            foreach (PrfType algorithm in approved)
                Assert.That(PrfFactory.Create(algorithm), Is.Not.Null, algorithm.ToString());
        });
    }
}
