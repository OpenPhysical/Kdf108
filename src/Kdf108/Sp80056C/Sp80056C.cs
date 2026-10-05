// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using System.Buffers.Binary;
using Kdf108.Internal;
using Org.BouncyCastle.Crypto;

namespace Kdf108;

/// <summary>The auxiliary function H for SP 800-56C Rev. 2 one-step key derivation (§4.1).</summary>
public sealed class OneStepFunction
{
    private readonly byte[]? _salt;

    private OneStepFunction(NistHashAlgorithm? hash, bool hmac, KmacVariant? kmac, ReadOnlySpan<byte> salt)
    {
        Hash = hash;
        IsHmac = hmac;
        Kmac = kmac;
        _salt = salt.IsEmpty ? null : salt.ToArray();
    }

    /// <summary>The hash for options 1 and 2, or <see langword="null"/> for KMAC.</summary>
    public NistHashAlgorithm? Hash { get; }

    /// <summary><see langword="true"/> for option 2, HMAC.</summary>
    public bool IsHmac { get; }

    /// <summary>The KMAC variant for option 3, or <see langword="null"/>.</summary>
    public KmacVariant? Kmac { get; }

    internal ReadOnlySpan<byte> Salt => _salt;

    /// <summary>Option 1: H(x) = hash(x).</summary>
    public static OneStepFunction HashFunction(NistHashAlgorithm hash) => new(Checked(hash), false, null, default);

    /// <summary>Option 2: H(x) = HMAC-hash(salt, x). An empty salt means the default: a block of zero bytes.</summary>
    public static OneStepFunction Hmac(NistHashAlgorithm hash, ReadOnlySpan<byte> salt = default) => new(Checked(hash), true, null, salt);

    /// <summary>
    /// Option 3: H(x) = KMAC(salt, x, L, "KDF"). An empty salt means the default: 164 zero bytes for
    /// KMAC128 or 132 for KMAC256. L must be a whole number of bytes.
    /// </summary>
    public static OneStepFunction KmacFunction(KmacVariant variant, ReadOnlySpan<byte> salt = default)
    {
        Sp800108.Strength(variant);
        return new OneStepFunction(null, false, variant, salt);
    }

    internal int MaxStrengthBits => Kmac is { } kmac ? Sp800108.Strength(kmac) : Hashes.OutputBits(Hash!.Value);

    /// <inheritdoc />
    public override string ToString() => Kmac?.ToString() ?? (IsHmac ? $"HMAC-{Hash}" : Hash!.Value.ToString());

    private static NistHashAlgorithm Checked(NistHashAlgorithm hash)
    {
        Hashes.OutputBits(hash);
        return hash;
    }
}

/// <summary>The randomness-extraction step of SP 800-56C Rev. 2 two-step key derivation (§5.1).</summary>
public sealed class Extraction
{
    private readonly byte[] _salt;

    private Extraction(Prf mac, Prf expansionPrf, byte[] salt)
    {
        Mac = mac;
        ExpansionPrf = expansionPrf;
        _salt = salt;
    }

    /// <summary>The extraction MAC.</summary>
    public Prf Mac { get; }

    /// <summary>
    /// The PRF the expansion step must use with the extracted key: HMAC with the same hash after
    /// HMAC extraction, or AES-128-CMAC after AES-CMAC extraction (the extracted key is 128 bits).
    /// </summary>
    public Prf ExpansionPrf { get; }

    internal ReadOnlySpan<byte> Salt => _salt;

    /// <summary>HMAC-hash extraction. An empty salt means the default: a block of zero bytes.</summary>
    public static Extraction Hmac(NistHashAlgorithm hash, ReadOnlySpan<byte> salt = default)
    {
        Prf prf = Prf.Hmac(hash);
        return new Extraction(prf, prf, salt.IsEmpty ? new byte[Hashes.BlockBytes(hash)] : salt.ToArray());
    }

    /// <summary>AES-CMAC extraction. The salt is the AES key: exactly <paramref name="keyBits"/> long, or empty for all zeros.</summary>
    public static Extraction AesCmac(int keyBits, ReadOnlySpan<byte> salt = default)
    {
        Prf prf = Prf.AesCmac(keyBits);
        if (!salt.IsEmpty && salt.Length * 8 != keyBits)
            throw new KdfParameterException($"The AES-CMAC salt must be {keyBits} bits.", nameof(salt));
        return new Extraction(prf, Prf.AesCmac(128), salt.IsEmpty ? new byte[keyBits / 8] : salt.ToArray());
    }

    internal int MaxStrengthBits => Mac.IsCmac ? 128 : Mac.OutputBits;

    /// <inheritdoc />
    public override string ToString() => Mac.ToString();
}

/// <summary>
/// Key derivation from an SP 800-56A shared secret Z, per NIST SP 800-56C Rev. 2. Use the one-step
/// method, or the two-step method (extract a key-derivation key, then expand it with SP 800-108).
/// </summary>
/// <remarks>
/// Secrets go in as spans and come out as new arrays that the caller owns. The target security
/// strength is checked against the chosen function. Invalid parameters throw <see cref="KdfParameterException"/>.
/// For dependency injection and logging, use <see cref="ISp80056CKdf"/>.
/// </remarks>
public static class Sp80056C
{
    private static readonly byte[] KmacCustomization = "KDF"u8.ToArray();

    /// <summary>One-step key derivation (§4): K(i) = H(counter || Z || FixedInfo).</summary>
    /// <param name="sharedSecret">Z.</param>
    /// <param name="function">The auxiliary function H.</param>
    /// <param name="fixedInfo">FixedInfo, for example AlgorithmID || PartyUInfo || PartyVInfo.</param>
    /// <param name="length">The output length L.</param>
    /// <param name="strength">The target security strength, at least 112 bits.</param>
    public static byte[] OneStep(
        ReadOnlySpan<byte> sharedSecret,
        OneStepFunction function,
        ReadOnlySpan<byte> fixedInfo,
        BitLength length,
        SecurityStrength strength)
    {
        ArgumentNullException.ThrowIfNull(function);
        RequireSecret(sharedSecret);
        RequireStrength(strength, function.MaxStrengthBits, function.ToString());
        return function.Kmac is { } kmac
            ? OneStepKmac(sharedSecret, function, kmac, fixedInfo, length)
            : OneStepHash(sharedSecret, function, fixedInfo, length);
    }

    /// <summary>The extraction step (§5.1): K_DK = MAC(salt, Z). Expand the result with <see cref="Sp800108"/> using <see cref="Extraction.ExpansionPrf"/>.</summary>
    /// <param name="sharedSecret">Z.</param>
    /// <param name="extraction">HMAC or AES-CMAC extraction and its salt.</param>
    /// <param name="strength">The target security strength, at least 112 bits.</param>
    public static byte[] Extract(ReadOnlySpan<byte> sharedSecret, Extraction extraction, SecurityStrength strength)
    {
        ArgumentNullException.ThrowIfNull(extraction);
        RequireSecret(sharedSecret);
        RequireStrength(strength, extraction.MaxStrengthBits, extraction.ToString());
        return Macs.Compute(extraction.Mac, extraction.Salt, sharedSecret);
    }

    /// <summary>
    /// Two-step key derivation (§5): extracts a key-derivation key from Z, then expands it with
    /// SP 800-108 using the PRF the extraction requires. To derive several keys from one Z, call
    /// <see cref="Extract"/> once and <see cref="Sp800108.Derive(ReadOnlySpan{byte}, Prf, KeyExpansion, BitLength)"/>
    /// once per key with distinct fixed input.
    /// </summary>
    public static byte[] TwoStep(
        ReadOnlySpan<byte> sharedSecret,
        Extraction extraction,
        KeyExpansion expansion,
        BitLength length,
        SecurityStrength strength)
    {
        byte[] kdk = Extract(sharedSecret, extraction, strength);
        try
        {
            return Sp800108.Derive(kdk, extraction.ExpansionPrf, expansion, length);
        }
        finally
        {
            Array.Clear(kdk);
        }
    }

    private static byte[] OneStepHash(ReadOnlySpan<byte> z, OneStepFunction function, ReadOnlySpan<byte> fixedInfo, BitLength length)
    {
        NistHashAlgorithm hash = function.Hash!.Value;
        int h = Hashes.OutputBits(hash) / 8;
        long repetitions = (length.Bits + (h * 8L) - 1) / (h * 8L);
        if (repetitions > uint.MaxValue)
            throw new KdfParameterException("The output needs more than 2^32 - 1 repetitions.", nameof(length));

        IMac? mac = null;
        IDigest? digest = null;
        if (function.IsHmac)
        {
            byte[] salt = function.Salt.IsEmpty ? new byte[Hashes.BlockBytes(hash)] : function.Salt.ToArray();
            mac = Macs.Create(Prf.Hmac(hash), salt);
        }
        else
        {
            digest = Hashes.CreateDigest(hash);
        }

        var output = new byte[length.ByteLength];
        Span<byte> block = stackalloc byte[64];
        block = block[..h];
        Span<byte> counter = stackalloc byte[4];
        try
        {
            int offset = 0;
            for (uint i = 1; i <= repetitions; i++)
            {
                BinaryPrimitives.WriteUInt32BigEndian(counter, i);
                if (mac is not null)
                {
                    mac.BlockUpdate(counter); mac.BlockUpdate(z); mac.BlockUpdate(fixedInfo); mac.DoFinal(block);
                }
                else
                {
                    digest!.BlockUpdate(counter); digest.BlockUpdate(z); digest.BlockUpdate(fixedInfo); digest.DoFinal(block);
                }

                int take = Math.Min(h, output.Length - offset);
                block[..take].CopyTo(output.AsSpan(offset));
                offset += take;
            }

            Bits.MaskTail(output, length.Bits);
            return output;
        }
        finally
        {
            block.Clear();
        }
    }

    private static byte[] OneStepKmac(ReadOnlySpan<byte> z, OneStepFunction function, KmacVariant kmac, ReadOnlySpan<byte> fixedInfo, BitLength length)
    {
        // With H_outputBits = L, one repetition suffices: K = KMAC(salt, 00000001 || Z || FixedInfo, L, "KDF").
        int strength = Sp800108.Strength(kmac);
        byte[] salt = function.Salt.IsEmpty ? new byte[strength == 128 ? 164 : 132] : function.Salt.ToArray();
        var input = new byte[4 + z.Length + fixedInfo.Length];
        try
        {
            BinaryPrimitives.WriteUInt32BigEndian(input, 1);
            z.CopyTo(input.AsSpan(4));
            fixedInfo.CopyTo(input.AsSpan(4 + z.Length));
            return Macs.Kmac(strength, salt, input, KmacCustomization, length.Bits);
        }
        finally
        {
            Array.Clear(input);
        }
    }

    private static void RequireSecret(ReadOnlySpan<byte> z)
    {
        if (z.IsEmpty)
            throw new KdfParameterException("The shared secret Z must not be empty.", "sharedSecret");
    }

    private static void RequireStrength(SecurityStrength strength, int maximum, string function)
    {
        if (strength.Bits < 112 || strength.Bits > maximum)
            throw new KdfParameterException($"{function} cannot support {strength} security (allowed: 112 to {maximum} bits).", nameof(strength));
    }
}
