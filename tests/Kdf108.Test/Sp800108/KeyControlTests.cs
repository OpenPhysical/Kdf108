// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System.Linq;
using System.Reflection;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;

namespace Kdf108.Test.Sp800108;

[TestFixture]
[Category("Unit")]
public class KeyControlTests
{
    private static readonly MethodInfo CreatePrfInputMethod =
        typeof(CounterModeKdf).GetMethod("CreatePrfInput", BindingFlags.NonPublic | BindingFlags.Static)!;

    private static readonly MethodInfo CreateCounterMethod =
        typeof(CounterModeKdf).GetMethod("CreateCounter", BindingFlags.NonPublic | BindingFlags.Static)!;

    [Test]
    public void CreatePrfInput_BeforeFixed_IncludesKeyControlBlock()
    {
        byte[] counter = (byte[])CreateCounterMethod.Invoke(null, new object[] { 1u, 8 })!;
        byte[] fixedInput = { 0xAA, 0xBB, 0xCC };
        byte[] k0 = { 0x11, 0x22 };

        byte[] input = (byte[])CreatePrfInputMethod.Invoke(
            null, new object[] { counter, fixedInput, CounterLocation.BeforeFixed, k0 })!;

        byte[] expected = counter.Concat(fixedInput).Concat(k0).ToArray();
        Assert.That(input, Is.EqualTo(expected));
    }

    [Test]
    public void CreatePrfInput_AfterFixed_IncludesKeyControlBlock()
    {
        byte[] counter = (byte[])CreateCounterMethod.Invoke(null, new object[] { 1u, 8 })!;
        byte[] fixedInput = { 0xAA, 0xBB, 0xCC };
        byte[] k0 = { 0x11, 0x22 };

        byte[] input = (byte[])CreatePrfInputMethod.Invoke(
            null, new object[] { counter, fixedInput, CounterLocation.AfterFixed, k0 })!;

        byte[] expected = fixedInput.Concat(k0).Concat(counter).ToArray();
        Assert.That(input, Is.EqualTo(expected));
    }
}

