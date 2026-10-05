// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;

namespace Kdf108;

/// <summary>The three SP 800-108 iteration modes.</summary>
public enum KdfMode
{
    /// <summary>Counter mode (SP 800-108r1 §4.1).</summary>
    Counter,
    /// <summary>Feedback mode (§4.2).</summary>
    Feedback,
    /// <summary>Double-pipeline iteration mode (§4.3).</summary>
    DoublePipeline
}

/// <summary>Where the counter [i] goes in counter mode.</summary>
public enum CounterPosition
{
    /// <summary><c>[i] || FixedInput</c>, the form defined in SP 800-108r1 §4.1.</summary>
    BeforeFixedInput,
    /// <summary><c>FixedInput || [i]</c>.</summary>
    AfterFixedInput
}

/// <summary>Where the counter [i] goes in feedback and double-pipeline mode, relative to the chaining value K(i-1) or A(i).</summary>
public enum IterationCounterPosition
{
    /// <summary><c>Chain || [i] || FixedInput</c>, the form defined in SP 800-108r1 §4.2 and §4.3.</summary>
    AfterIteration,
    /// <summary><c>[i] || Chain || FixedInput</c>.</summary>
    BeforeIteration,
    /// <summary><c>Chain || FixedInput || [i]</c>.</summary>
    AfterFixedInput
}

/// <summary>
/// Describes one SP 800-108 expansion: the iteration mode, the fixed input data, and the counter
/// layout. Use <see cref="Sp800108.FixedInput"/> for the conventional
/// <c>Label || 0x00 || Context || [L]</c> fixed input. Instances are immutable.
/// </summary>
public sealed class KeyExpansion
{
    internal enum Layout { CounterBefore, CounterAfter, CounterMiddle, AfterIteration, BeforeIteration, ChainAfterFixed, NoCounter }

    private readonly byte[] _fixedInput;
    private readonly byte[] _afterCounter;
    private readonly byte[] _iv;

    private KeyExpansion(KdfMode mode, Layout layout, int counterBits, ReadOnlySpan<byte> fixedInput, ReadOnlySpan<byte> afterCounter, ReadOnlySpan<byte> iv)
    {
        if (layout != Layout.NoCounter && counterBits is not (8 or 16 or 24 or 32))
            throw new KdfParameterException("The counter width r must be 8, 16, 24, or 32 bits.", nameof(counterBits));
        Mode = mode;
        CounterLayout = layout;
        CounterBits = layout == Layout.NoCounter ? 0 : counterBits;
        _fixedInput = fixedInput.ToArray();
        _afterCounter = afterCounter.ToArray();
        _iv = iv.ToArray();
    }

    /// <summary>The iteration mode.</summary>
    public KdfMode Mode { get; }

    /// <summary>The counter width r in bits, or 0 when the mode runs without a counter.</summary>
    public int CounterBits { get; }

    internal Layout CounterLayout { get; }
    internal ReadOnlySpan<byte> FixedInputSpan => _fixedInput;
    internal ReadOnlySpan<byte> AfterCounterSpan => _afterCounter;
    internal ReadOnlySpan<byte> IvSpan => _iv;

    /// <summary>Counter mode with the counter before or after the fixed input.</summary>
    /// <param name="fixedInput">The fixed input data, typically from <see cref="Sp800108.FixedInput"/>.</param>
    /// <param name="counterBits">The counter width r: 8, 16, 24, or 32.</param>
    /// <param name="position">Where the counter goes.</param>
    public static KeyExpansion Counter(ReadOnlySpan<byte> fixedInput, int counterBits = 32, CounterPosition position = CounterPosition.BeforeFixedInput) =>
        new(KdfMode.Counter,
            position switch
            {
                CounterPosition.BeforeFixedInput => Layout.CounterBefore,
                CounterPosition.AfterFixedInput => Layout.CounterAfter,
                _ => throw new KdfParameterException($"Unknown counter position {position}.", nameof(position))
            },
            counterBits, fixedInput, default, default);

    /// <summary>Counter mode with the counter in the middle of the fixed input: <c>Before || [i] || After</c>.</summary>
    public static KeyExpansion CounterInMiddle(ReadOnlySpan<byte> beforeCounter, ReadOnlySpan<byte> afterCounter, int counterBits = 32) =>
        new(KdfMode.Counter, Layout.CounterMiddle, counterBits, beforeCounter, afterCounter, default);

    /// <summary>Feedback mode. K(0) is <paramref name="iv"/>, which may be empty.</summary>
    /// <param name="fixedInput">The fixed input data.</param>
    /// <param name="iv">The initial chaining value K(0).</param>
    /// <param name="useCounter">Whether each PRF input includes the counter [i].</param>
    /// <param name="counterBits">The counter width r: 8, 16, 24, or 32. Ignored without a counter.</param>
    /// <param name="position">Where the counter goes relative to K(i-1).</param>
    public static KeyExpansion Feedback(ReadOnlySpan<byte> fixedInput, ReadOnlySpan<byte> iv, bool useCounter = true, int counterBits = 32, IterationCounterPosition position = IterationCounterPosition.AfterIteration) =>
        new(KdfMode.Feedback, ChainLayout(useCounter, position), counterBits, fixedInput, default, iv);

    /// <summary>Double-pipeline iteration mode. A(0) is the fixed input.</summary>
    /// <param name="fixedInput">The fixed input data.</param>
    /// <param name="useCounter">Whether each PRF input includes the counter [i].</param>
    /// <param name="counterBits">The counter width r: 8, 16, 24, or 32. Ignored without a counter.</param>
    /// <param name="position">Where the counter goes relative to A(i).</param>
    public static KeyExpansion DoublePipeline(ReadOnlySpan<byte> fixedInput, bool useCounter = true, int counterBits = 32, IterationCounterPosition position = IterationCounterPosition.AfterIteration) =>
        new(KdfMode.DoublePipeline, ChainLayout(useCounter, position), counterBits, fixedInput, default, default);

    private static Layout ChainLayout(bool useCounter, IterationCounterPosition position) =>
        !useCounter ? Layout.NoCounter : position switch
        {
            IterationCounterPosition.AfterIteration => Layout.AfterIteration,
            IterationCounterPosition.BeforeIteration => Layout.BeforeIteration,
            IterationCounterPosition.AfterFixedInput => Layout.ChainAfterFixed,
            _ => throw new KdfParameterException($"Unknown counter position {position}.", nameof(position))
        };
}
