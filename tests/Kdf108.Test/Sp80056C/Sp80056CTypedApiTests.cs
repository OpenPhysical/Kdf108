// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using AwesomeAssertions;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Sp80056C;

namespace Kdf108.Test.Sp80056C;

[TestFixture]
public class Sp80056CTypedApiTests
{
    [TestCase("Kdf108.Domain.Sp80056C.Sp80056COptions")]
    [TestCase("Kdf108.Domain.Sp80056C.Sp80056COptionsBuilder")]
    [TestCase("Kdf108.Domain.Sp80056C.Sp80056COneStepKdf")]
    [TestCase("Kdf108.Domain.Sp80056C.Sp80056CTwoStepKdf")]
    public void LegacyMutableSurface_IsNotPublic(string typeName)
    {
        var type = typeof(OneStepKdfRequest).Assembly.GetType(typeName, throwOnError: true)!;

        type.IsPublic.Should().BeFalse();
    }

    [Test]
    public void OneStepHash_MatchesPinnedVector()
    {
        var request = new OneStepKdfRequest(
            Convert.FromHexString("AFC4E154498D4770AA8365F6903DC83B"),
            Convert.FromHexString("662AF20379B29D5EF813E655"),
            BitLength.Create(128),
            SecurityStrength.Bits128,
            OneStepAuxiliaryFunction.HashFunction(NistHashAlgorithm.Sha256));

        Sp80056COneStep.Derive(request).Should().Equal(
            Convert.FromHexString("F0B80D6AE4C1E19E2105A37024E35DC6"));
    }

    [Test]
    public void OneStepHmac_UsesSaltAsMacKey()
    {
        var request = new OneStepKdfRequest(
            Convert.FromHexString("6EE6C00D70A6CD14BD5A4E8FCFEC8386"),
            Convert.FromHexString("861AA2886798231259BD0314"),
            BitLength.Create(128),
            SecurityStrength.Bits128,
            OneStepAuxiliaryFunction.HmacFunction(
                NistHashAlgorithm.Sha256,
                Convert.FromHexString("532F5131E0A2FECC722F87E5AA2062CB")));

        Sp80056COneStep.Derive(request).Should().Equal(
            Convert.FromHexString("13479E9A91DD20FDD757D68FFE8869FB"));
    }

    [Test]
    public void OneStep_PreservesRequestedPartialBitLength()
    {
        var request = new OneStepKdfRequest(
            Convert.FromHexString("0001020304050607"),
            Convert.FromHexString("A0A1A2"),
            BitLength.Create(9),
            SecurityStrength.Bits112,
            OneStepAuxiliaryFunction.HashFunction(NistHashAlgorithm.Sha256));

        var output = Sp80056COneStep.Derive(request);

        output.Should().HaveCount(2);
        (output[1] & 0x7F).Should().Be(0);
    }

    [Test]
    public void TwoStepHmacCounter_MatchesIndependentPinnedVector()
    {
        var request = new TwoStepKdfRequest(
            Convert.FromHexString("000102030405060708090A0B0C0D0E0F"),
            TwoStepExtraction.HmacFunction(
                NistHashAlgorithm.Sha256,
                Convert.FromHexString("101112131415161718191A1B1C1D1E1F")),
            SecurityStrength.Bits128,
            new[]
            {
                KeyExpansion.CounterMode(
                    Convert.FromHexString("A0A1A2A3A4A5"),
                    BitLength.Create(257),
                    32,
                    CounterLocation.BeforeFixed)
            });

        Sp80056CTwoStep.Derive(request)[0].Should().Equal(
            Convert.FromHexString("A6F6BD8476D30AB690A3B031B9831CCA1B61352326D8AE2C59B6EE494DFC832780"));
    }

    [Test]
    public void TwoStep_RejectsDuplicateFixedInfoBeforeDerivation()
    {
        Action act = () => new TwoStepKdfRequest(
            new byte[] { 1 },
            TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha256),
            SecurityStrength.Bits112,
            new[]
            {
                KeyExpansion.CounterMode(new byte[] { 2 }, BitLength.Create(128)),
                KeyExpansion.CounterMode(new byte[] { 2 }, BitLength.Create(256))
            });

        act.Should().Throw<ArgumentException>().WithMessage("*pairwise distinct*");
    }

    [Test]
    public void AesCmacExtraction_RejectsWrongSaltSize()
    {
        Action act = () => TwoStepExtraction.AesCmacFunction(192, new byte[16]);

        act.Should().Throw<ArgumentException>().WithMessage("*selected AES key size*");
    }
}
