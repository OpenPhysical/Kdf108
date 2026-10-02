// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#pragma warning disable CS1591

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Kdf108.Domain.Kdf;
using Kdf108.Domain.Kdf.Modes;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Kdf108.Domain.Sp80056C;

/// <summary>SP 800-56C Rev. 2 extraction followed by one or more SP 800-108 expansions.</summary>
public static class Sp80056CTwoStep
{
    public static IReadOnlyList<byte[]> Derive(TwoStepKdfRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var z = request.CopySharedSecret();
        byte[]? kdk = null;
        var results = new List<byte[]>(request.Expansions.Count);
        try
        {
            kdk = Extract(request.Extraction, z);
            foreach (var expansion in request.Expansions)
                results.Add(Expand(request.Extraction, kdk, expansion));

            return results.AsReadOnly();
        }
        catch
        {
            foreach (var result in results)
                CryptographicOperations.ZeroMemory(result);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(z);
            if (kdk is not null)
                CryptographicOperations.ZeroMemory(kdk);
        }
    }

    private static byte[] Extract(TwoStepExtraction extraction, byte[] z)
    {
        return extraction switch
        {
            TwoStepExtraction.Hmac hmac => ExtractHmac(hmac, z),
            TwoStepExtraction.AesCmac cmac => ExtractAesCmac(cmac, z),
            _ => throw new ArgumentOutOfRangeException(nameof(extraction))
        };
    }

    private static byte[] ExtractHmac(TwoStepExtraction.Hmac extraction, byte[] z)
    {
        var salt = extraction.CopySalt() ?? new byte[Sp80056CAlgorithmInfo.BlockBytes(extraction.Algorithm)];
        try
        {
            var hmac = new HMac(Sp80056COneStep.CreateDigest(extraction.Algorithm));
            hmac.Init(new KeyParameter(salt));
            hmac.BlockUpdate(z, 0, z.Length);
            var output = new byte[hmac.GetMacSize()];
            hmac.DoFinal(output, 0);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    private static byte[] ExtractAesCmac(TwoStepExtraction.AesCmac extraction, byte[] z)
    {
        var salt = extraction.CopySalt() ?? new byte[extraction.KeyBits / 8];
        try
        {
            var cmac = new CMac(new AesEngine());
            cmac.Init(new KeyParameter(salt));
            cmac.BlockUpdate(z, 0, z.Length);
            var output = new byte[cmac.GetMacSize()];
            cmac.DoFinal(output, 0);
            return output;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(salt);
        }
    }

    private static byte[] Expand(TwoStepExtraction extraction, byte[] kdk, KeyExpansion expansion)
    {
        PrfType prf = extraction switch
        {
            TwoStepExtraction.Hmac hmac => Sp80056CAlgorithmInfo.ToPrf(hmac.Algorithm),
            TwoStepExtraction.AesCmac => PrfType.CmacAes128,
            _ => throw new ArgumentOutOfRangeException(nameof(extraction))
        };

        var options = KdfOptions.CreateBuilder()
            .WithPrfType(prf)
            .WithCounterLengthBits(expansion.CounterBits)
            .WithUseCounter(expansion.UseCounter)
            .WithCounterLocation(expansion.CounterLocation)
            .WithMaxBitsAllowed(expansion.OutputLength.Bits)
            .Build();
        var fixedInfo = expansion.CopyFixedInfo();
        try
        {
            return expansion switch
            {
                KeyExpansion.Counter => new CounterModeKdf().DeriveWithFixedInput(kdk, fixedInfo, expansion.OutputLength.Bits, options),
                KeyExpansion.Feedback feedback => DeriveFeedback(kdk, fixedInfo, feedback, options),
                KeyExpansion.DoublePipeline => new DoublePipelineKdf(expansion.UseCounter).DeriveWithFixedInput(kdk, fixedInfo, expansion.OutputLength.Bits, options),
                _ => throw new ArgumentOutOfRangeException(nameof(expansion))
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fixedInfo);
        }
    }

    private static byte[] DeriveFeedback(byte[] kdk, byte[] fixedInfo, KeyExpansion.Feedback feedback, KdfOptions options)
    {
        var iv = feedback.CopyIv() ?? Array.Empty<byte>();
        try
        {
            return new FeedbackModeKdf(feedback.UseCounter).DeriveWithFixedInput(
                kdk,
                fixedInfo,
                iv,
                feedback.OutputLength.Bits,
                options);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(iv);
        }
    }
}
