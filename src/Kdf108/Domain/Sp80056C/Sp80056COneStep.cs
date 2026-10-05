// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#pragma warning disable CS1591

using System;
using Kdf108.Internal;
using Kdf108.Domain.Kdf;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Kdf108.Domain.Sp80056C;

/// <summary>SP 800-56C Rev. 2 one-step key derivation.</summary>
public static class Sp80056COneStep
{
    private static readonly byte[] KmacCustomization = { 0x4B, 0x44, 0x46 };

    public static byte[] Derive(OneStepKdfRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var z = request.CopySharedSecret();
        var fixedInfo = request.CopyFixedInfo();
        try
        {
            int hOutputBits = request.AuxiliaryFunction switch
            {
                OneStepAuxiliaryFunction.Hash hash => Sp80056CAlgorithmInfo.OutputBits(hash.Algorithm),
                OneStepAuxiliaryFunction.Hmac hmac => Sp80056CAlgorithmInfo.OutputBits(hmac.Algorithm),
                OneStepAuxiliaryFunction.Kmac kmac => checked((int)kmac.OutputLength.Bits),
                _ => throw new ArgumentOutOfRangeException(nameof(request))
            };

            ulong repetitions = checked((ulong)((request.OutputLength.Bits + hOutputBits - 1) / hOutputBits));
            if (repetitions == 0 || repetitions > uint.MaxValue)
                throw new ArgumentOutOfRangeException(nameof(request), "Output length exceeds the 32-bit counter limit.");

            var result = new byte[request.OutputLength.ByteLength];
            int offset = 0;
            for (ulong blockIndex = 1; blockIndex <= repetitions; blockIndex++)
            {
                uint counter = checked((uint)blockIndex);
                var input = BuildInput(counter, z, fixedInfo);
                byte[] block;
                try
                {
                    block = ComputeBlock(request.AuxiliaryFunction, input, hOutputBits);
                }
                finally
                {
                    SecureMemory.Clear(input);
                }

                try
                {
                    int count = Math.Min(block.Length, result.Length - offset);
                    Buffer.BlockCopy(block, 0, result, offset, count);
                    offset += count;
                }
                finally
                {
                    SecureMemory.Clear(block);
                }
            }

            MaskUnusedBits(result, request.OutputLength.Bits);
            return result;
        }
        finally
        {
            SecureMemory.Clear(z);
            SecureMemory.Clear(fixedInfo);
        }
    }

    private static byte[] BuildInput(uint counter, byte[] z, byte[] fixedInfo)
    {
        var input = new byte[checked(4 + z.Length + fixedInfo.Length)];
        input[0] = (byte)(counter >> 24);
        input[1] = (byte)(counter >> 16);
        input[2] = (byte)(counter >> 8);
        input[3] = (byte)counter;
        Buffer.BlockCopy(z, 0, input, 4, z.Length);
        Buffer.BlockCopy(fixedInfo, 0, input, 4 + z.Length, fixedInfo.Length);
        return input;
    }

    private static byte[] ComputeBlock(OneStepAuxiliaryFunction function, byte[] input, int outputBits)
    {
        return function switch
        {
            OneStepAuxiliaryFunction.Hash hash => ComputeHash(hash.Algorithm, input),
            OneStepAuxiliaryFunction.Hmac hmac => ComputeHmac(hmac, input),
            OneStepAuxiliaryFunction.Kmac kmac => ComputeKmac(kmac, input, outputBits),
            _ => throw new ArgumentOutOfRangeException(nameof(function))
        };
    }

    private static byte[] ComputeHash(NistHashAlgorithm algorithm, byte[] input)
    {
        var digest = CreateDigest(algorithm);
        digest.BlockUpdate(input, 0, input.Length);
        var output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);
        return output;
    }

    private static byte[] ComputeHmac(OneStepAuxiliaryFunction.Hmac function, byte[] input)
    {
        var salt = function.CopySalt() ?? new byte[Sp80056CAlgorithmInfo.BlockBytes(function.Algorithm)];
        try
        {
            var hmac = new HMac(CreateDigest(function.Algorithm));
            hmac.Init(new KeyParameter(salt));
            hmac.BlockUpdate(input, 0, input.Length);
            var output = new byte[hmac.GetMacSize()];
            hmac.DoFinal(output, 0);
            return output;
        }
        finally
        {
            SecureMemory.Clear(salt);
        }
    }

    private static byte[] ComputeKmac(OneStepAuxiliaryFunction.Kmac function, byte[] input, int outputBits)
    {
        var salt = function.CopySalt() ?? new byte[function.Strength == 128 ? 164 : 132];
        try
        {
            var kmac = new KMac(function.Strength, KmacCustomization);
            kmac.Init(new KeyParameter(salt));
            kmac.BlockUpdate(input, 0, input.Length);
            var output = new byte[checked((outputBits + 7) / 8)];
            kmac.OutputFinal(output, 0, output.Length);
            MaskUnusedBits(output, outputBits);
            return output;
        }
        finally
        {
            SecureMemory.Clear(salt);
        }
    }

    internal static IDigest CreateDigest(NistHashAlgorithm algorithm) => algorithm switch
    {
        NistHashAlgorithm.Sha1 => new Sha1Digest(),
        NistHashAlgorithm.Sha224 => new Sha224Digest(),
        NistHashAlgorithm.Sha256 => new Sha256Digest(),
        NistHashAlgorithm.Sha512_224 => new Sha512tDigest(224),
        NistHashAlgorithm.Sha512_256 => new Sha512tDigest(256),
        NistHashAlgorithm.Sha384 => new Sha384Digest(),
        NistHashAlgorithm.Sha512 => new Sha512Digest(),
        NistHashAlgorithm.Sha3_224 => new Sha3Digest(224),
        NistHashAlgorithm.Sha3_256 => new Sha3Digest(256),
        NistHashAlgorithm.Sha3_384 => new Sha3Digest(384),
        NistHashAlgorithm.Sha3_512 => new Sha3Digest(512),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };

    private static void MaskUnusedBits(byte[] output, long bitLength)
    {
        int remainder = (int)(bitLength & 7);
        if (remainder != 0)
            output[^1] &= (byte)(0xFF << (8 - remainder));
    }
}
