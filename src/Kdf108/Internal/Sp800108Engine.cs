// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Org.BouncyCastle.Crypto;

namespace Kdf108.Internal;

/// <summary>
/// The one SP 800-108 iteration loop for counter, feedback, and double-pipeline modes. The PRF is
/// keyed once, each PRF input is fed segment by segment (no concatenation buffers), and output is
/// written straight into the result.
/// </summary>
internal static class Sp800108Engine
{
    private const int MaxMacBytes = 64;

    internal static byte[] Derive(ReadOnlySpan<byte> keyDerivationKey, Prf prf, KeyExpansion expansion, BitLength length)
    {
        ArgumentNullException.ThrowIfNull(prf);
        ArgumentNullException.ThrowIfNull(expansion);
        if (length.Bits > uint.MaxValue)
            throw new KdfParameterException("SP 800-108 output is limited to 2^32 - 1 bits.", nameof(length));
        if (keyDerivationKey.IsEmpty)
            throw new KdfParameterException("The key-derivation key must not be empty.", nameof(keyDerivationKey));

        int h = prf.OutputBits / 8;
        long repetitions = (length.Bits + (h * 8L) - 1) / (h * 8L);
        if (expansion.CounterBits > 0 && repetitions > (1L << expansion.CounterBits) - 1)
            throw new KdfParameterException(
                $"{length} needs {repetitions} PRF blocks, more than an {expansion.CounterBits}-bit counter can number.", nameof(length));

        IMac mac = Macs.Create(prf, keyDerivationKey);
        var output = new byte[length.ByteLength];
        Span<byte> block = stackalloc byte[MaxMacBytes];
        block = block[..h];
        Span<byte> counter = stackalloc byte[4];
        counter = counter[..(expansion.CounterBits / 8)];
        var chain = new byte[Math.Max(h, expansion.IvSpan.Length)];
        int chainLength = expansion.Mode == KdfMode.Feedback ? expansion.IvSpan.Length : 0;
        expansion.IvSpan.CopyTo(chain);

        try
        {
            ReadOnlySpan<byte> fixedInput = expansion.FixedInputSpan;
            int offset = 0;
            for (uint i = 1; i <= repetitions; i++)
            {
                if (expansion.Mode == KdfMode.DoublePipeline)
                {
                    // A(i) = PRF(KI, A(i-1)), with A(0) = FixedInput.
                    mac.BlockUpdate(i == 1 ? fixedInput : chain.AsSpan(0, h));
                    mac.DoFinal(chain);
                    chainLength = h;
                }

                WriteCounter(counter, i);
                FeedInput(mac, expansion, counter, chain.AsSpan(0, chainLength), fixedInput);
                mac.DoFinal(block);

                int take = Math.Min(h, output.Length - offset);
                block[..take].CopyTo(output.AsSpan(offset));
                offset += take;

                if (expansion.Mode == KdfMode.Feedback)
                {
                    block.CopyTo(chain);
                    chainLength = h;
                }
            }

            Bits.MaskTail(output, length.Bits);
            return output;
        }
        catch
        {
            Array.Clear(output);
            throw;
        }
        finally
        {
            block.Clear();
            Array.Clear(chain);
        }
    }

    private static void FeedInput(IMac mac, KeyExpansion expansion, ReadOnlySpan<byte> counter, ReadOnlySpan<byte> chain, ReadOnlySpan<byte> fixedInput)
    {
        switch (expansion.CounterLayout)
        {
            case KeyExpansion.Layout.CounterBefore:
                mac.BlockUpdate(counter); mac.BlockUpdate(fixedInput); break;
            case KeyExpansion.Layout.CounterAfter:
                mac.BlockUpdate(fixedInput); mac.BlockUpdate(counter); break;
            case KeyExpansion.Layout.CounterMiddle:
                mac.BlockUpdate(fixedInput); mac.BlockUpdate(counter); mac.BlockUpdate(expansion.AfterCounterSpan); break;
            case KeyExpansion.Layout.AfterIteration:
                mac.BlockUpdate(chain); mac.BlockUpdate(counter); mac.BlockUpdate(fixedInput); break;
            case KeyExpansion.Layout.BeforeIteration:
                mac.BlockUpdate(counter); mac.BlockUpdate(chain); mac.BlockUpdate(fixedInput); break;
            case KeyExpansion.Layout.ChainAfterFixed:
                mac.BlockUpdate(chain); mac.BlockUpdate(fixedInput); mac.BlockUpdate(counter); break;
            case KeyExpansion.Layout.NoCounter:
                mac.BlockUpdate(chain); mac.BlockUpdate(fixedInput); break;
        }
    }

    private static void WriteCounter(Span<byte> counter, uint i)
    {
        for (int k = counter.Length - 1; k >= 0; k--)
        {
            counter[k] = (byte)i;
            i >>= 8;
        }
    }
}
