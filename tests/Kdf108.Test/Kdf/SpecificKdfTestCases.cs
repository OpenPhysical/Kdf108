// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#region

using System.IO;
using System.Reflection;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Kdf108.Internal;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

#endregion

namespace Kdf108.Test.Kdf
{
    /// <summary>
    ///     Tests for specific KDF test cases that need special attention
    /// </summary>
    [TestFixture]
    public class SpecificKdfTestCases
    {
        [Test]
        public void TestSpecificCmacCounter()
        {
            // Test vector from the original failing test
            byte[] key = ConvertCompat.FromHexString("DFF1E50AC0B69DC40F1051D46C2B069C");
            byte[] fixedInput =
                ConvertCompat.FromHexString(
                    "C16E6E02C5A3DCC8D78B9AC1306877761310455B4E41469951D9E6C2245A064B33FD8C3B01203A7824485BF0A64060C4648B707D2607935699316EA5");
            byte[] expectedOutput = ConvertCompat.FromHexString("8BE8F0869B3C0BA97B71863D1B9F7813");

            // First, directly test CMAC-AES128
            byte[] input;
            byte[] counter = { 0x01 }; // 8-bit counter with value 1

            // Properly scope the disposable objects
            using (MemoryStream memory = new())
            {
                using (BinaryWriter writer = new(memory))
                {
                    writer.Write(counter);
                    writer.Write(fixedInput);
                }

                input = memory.ToArray();
            }

            // Manual CMAC calculation using BouncyCastle directly
            AesEngine engine = new();
            CMac cmac = new(engine);
            cmac.Init(new KeyParameter(key));
            cmac.BlockUpdate(input, 0, input.Length);

            byte[] output = new byte[16];
            cmac.DoFinal(output, 0);

            // Use assertions instead of console output for verification
            Assert.That(output, Is.EqualTo(expectedOutput),
                "Manual CMAC-AES128 calculation did not produce expected output");

            CounterModeKdf kdf = new();
            byte[] result = kdf.DeriveWithSplitFixedInput(
                key,
                new byte[0],
                fixedInput,
                128,
                new KdfOptions(prfType: PrfType.CmacAes128, counterLengthBits: 8, // 8-bit counter
                    useCounter: true, counterLocation: CounterLocation.BeforeFixed));

            Assert.That(result, Is.EqualTo(expectedOutput),
                "CMAC AES-128 KDF (raw counter mode) did not produce expected output");
        }

        /// <summary>
        ///     Test the counter creation separately to ensure it's working correctly
        /// </summary>
        [Test]
        public void TestCreateCounter()
        {
            // Use reflection to access the private method
            CounterModeKdf kdf = new();
            MethodInfo? methodInfo = kdf.GetType().GetMethod("CreateCounter",
                BindingFlags.NonPublic | BindingFlags.Static);

            Assert.That(methodInfo, Is.Not.Null, "Could not find CreateCounter method via reflection");
            MethodInfo method = methodInfo!;
            try
            {
                // Test 8-bit counter
                byte[] counter8Bit = (byte[])method.Invoke(null, new object[] { 1u, 8 })!;
                Assert.That(counter8Bit, Is.EqualTo(new byte[] { 0x01 }), "8-bit counter incorrect");

                // Test 16-bit counter
                byte[] counter16Bit = (byte[])method.Invoke(null, new object[] { 1u, 16 })!;
                Assert.That(counter16Bit, Is.EqualTo(new byte[] { 0x00, 0x01 }), "16-bit counter incorrect");

                // Test 24-bit counter
                byte[] counter24Bit = (byte[])method.Invoke(null, new object[] { 1u, 24 })!;
                Assert.That(counter24Bit, Is.EqualTo(new byte[] { 0x00, 0x00, 0x01 }), "24-bit counter incorrect");

                // Test 32-bit counter
                byte[] counter32Bit = (byte[])method.Invoke(null, new object[] { 1u, 32 })!;
                Assert.That(counter32Bit, Is.EqualTo(new byte[] { 0x00, 0x00, 0x00, 0x01 }), "32-bit counter incorrect");
            }
            catch (TargetInvocationException ex)
            {
                throw ex.InnerException ?? ex;
            }
        }
    }
}
