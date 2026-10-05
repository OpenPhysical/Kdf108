// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Linq;
using System.Reflection;
using AwesomeAssertions;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Sp80056A;
using Kdf108.Domain.Sp80056C;

namespace Kdf108.Test.Security;

[TestFixture]
public class SecretLifetimeTests
{
    [Test]
    public void SharedSecret_DisposeZeroesOwnedBufferAndRejectsUse()
    {
        var secret = new SharedSecret(new byte[] { 1, 2, 3, 4 });
        byte[] owned = GetPrivateBuffer(secret, "_value");

        secret.Dispose();

        owned.Should().OnlyContain(value => value == 0);
        Action read = () => secret.ToArray();
        read.Should().Throw<ObjectDisposedException>();
    }

    [Test]
    public void OneStepRequest_DisposeZeroesSecretAndRejectsDerivation()
    {
        var request = new OneStepKdfRequest(
            new byte[] { 1, 2, 3, 4 },
            Array.Empty<byte>(),
            BitLength.Create(128),
            SecurityStrength.Bits112,
            OneStepAuxiliaryFunction.HashFunction(NistHashAlgorithm.Sha256));
        byte[] owned = GetPrivateBuffer(request, "_sharedSecret");

        request.Dispose();

        owned.Should().OnlyContain(value => value == 0);
        Action derive = () => Sp80056COneStep.Derive(request);
        derive.Should().Throw<ObjectDisposedException>();
    }

    [Test]
    public void TwoStepRequest_DisposeZeroesSecretAndRejectsDerivation()
    {
        var request = new TwoStepKdfRequest(
            new byte[] { 1, 2, 3, 4 },
            TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha256),
            SecurityStrength.Bits112,
            new[] { KeyExpansion.CounterMode(Array.Empty<byte>(), BitLength.Create(128)) });
        byte[] owned = GetPrivateBuffer(request, "_sharedSecret");

        request.Dispose();

        owned.Should().OnlyContain(value => value == 0);
        Action derive = () => Sp80056CTwoStep.Derive(request);
        derive.Should().Throw<ObjectDisposedException>();
    }

    private static byte[] GetPrivateBuffer(object instance, string name) =>
        (byte[])instance.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(instance)!;
}
