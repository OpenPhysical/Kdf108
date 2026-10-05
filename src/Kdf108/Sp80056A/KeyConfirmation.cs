// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Internal;
using Org.BouncyCastle.Utilities;

namespace Kdf108;

/// <summary>A party in SP 800-56A: U is the initiator, V the responder.</summary>
public enum Party
{
    /// <summary>Party U, the initiator.</summary>
    U,
    /// <summary>Party V, the responder.</summary>
    V
}

/// <summary>Whether one party or both confirm the derived key.</summary>
public enum KeyConfirmationMode
{
    /// <summary>Only the provider sends a tag (message "KC_1_U" or "KC_1_V").</summary>
    Unilateral,
    /// <summary>Both parties send tags (message "KC_2_U" or "KC_2_V").</summary>
    Bilateral
}

/// <summary>The MAC used for key confirmation (SP 800-56A Rev. 3 §5.9): HMAC, AES-CMAC, or KMAC.</summary>
public sealed record KeyConfirmationMac
{
    private KeyConfirmationMac(Prf? prf, KmacVariant? kmac)
    {
        Prf = prf;
        Kmac = kmac;
    }

    /// <summary>The HMAC or AES-CMAC function, or <see langword="null"/> for KMAC.</summary>
    public Prf? Prf { get; }

    /// <summary>The KMAC variant, or <see langword="null"/> for HMAC and AES-CMAC.</summary>
    public KmacVariant? Kmac { get; }

    /// <summary>HMAC with an approved hash.</summary>
    public static KeyConfirmationMac Hmac(NistHashAlgorithm hash) => new(Kdf108.Prf.Hmac(hash), null);

    /// <summary>AES-CMAC with a 128-, 192-, or 256-bit key.</summary>
    public static KeyConfirmationMac AesCmac(int keyBits) => new(Kdf108.Prf.AesCmac(keyBits), null);

    /// <summary>KMAC128 or KMAC256 with customization string "KC". The tag length is KMAC's output length L.</summary>
    public static KeyConfirmationMac KmacFunction(KmacVariant variant)
    {
        Sp800108.Strength(variant);
        return new KeyConfirmationMac(null, variant);
    }

    internal int MaxTagBits => Prf?.OutputBits ?? int.MaxValue;

    /// <inheritdoc />
    public override string ToString() => Prf?.ToString() ?? Kmac!.Value.ToString();
}

/// <summary>The public inputs to key-confirmation MacData: who confirms, the identifiers, and the ephemeral data.</summary>
public sealed class KeyConfirmationContext
{
    private readonly byte[] _partyUId;
    private readonly byte[] _partyVId;
    private readonly byte[] _partyUEphemeralData;
    private readonly byte[] _partyVEphemeralData;
    private readonly byte[] _text;

    /// <summary>Creates the context.</summary>
    /// <param name="mode">Unilateral or bilateral.</param>
    /// <param name="provider">The party computing this tag.</param>
    /// <param name="partyUId">ID_U.</param>
    /// <param name="partyVId">ID_V.</param>
    /// <param name="partyUEphemeralData">U's ephemeral public key or nonce, or empty.</param>
    /// <param name="partyVEphemeralData">V's ephemeral public key or nonce, or empty.</param>
    /// <param name="text">Optional extra text appended to MacData.</param>
    public KeyConfirmationContext(
        KeyConfirmationMode mode,
        Party provider,
        ReadOnlySpan<byte> partyUId,
        ReadOnlySpan<byte> partyVId,
        ReadOnlySpan<byte> partyUEphemeralData,
        ReadOnlySpan<byte> partyVEphemeralData,
        ReadOnlySpan<byte> text = default)
    {
        if (partyUId.IsEmpty) throw new KdfParameterException("ID_U must not be empty.", nameof(partyUId));
        if (partyVId.IsEmpty) throw new KdfParameterException("ID_V must not be empty.", nameof(partyVId));
        Mode = mode;
        Provider = provider;
        _partyUId = partyUId.ToArray();
        _partyVId = partyVId.ToArray();
        _partyUEphemeralData = partyUEphemeralData.ToArray();
        _partyVEphemeralData = partyVEphemeralData.ToArray();
        _text = text.ToArray();
    }

    /// <summary>Unilateral or bilateral.</summary>
    public KeyConfirmationMode Mode { get; }

    /// <summary>The party computing this tag.</summary>
    public Party Provider { get; }

    /// <summary>
    /// MacData = message || ID_P || ID_R || EphemData_P || EphemData_R {|| Text}, where P is the
    /// provider and R the recipient (§5.9.1).
    /// </summary>
    public byte[] EncodeMacData()
    {
        byte[] message = System.Text.Encoding.ASCII.GetBytes($"KC_{(Mode == KeyConfirmationMode.Bilateral ? 2 : 1)}_{Provider}");
        bool u = Provider == Party.U;
        return Arrays.ConcatenateAll(
            message,
            u ? _partyUId : _partyVId,
            u ? _partyVId : _partyUId,
            u ? _partyUEphemeralData : _partyVEphemeralData,
            u ? _partyVEphemeralData : _partyUEphemeralData,
            _text);
    }
}

/// <summary>
/// SP 800-56A Rev. 3 §5.9 key confirmation: MacTag = T_MacTagLen[MAC(MacKey, MacData)].
/// For dependency injection and logging, use <see cref="IKeyConfirmation"/>.
/// </summary>
public static class KeyConfirmation
{
    private static readonly byte[] KmacCustomization = "KC"u8.ToArray();

    /// <summary>Computes the tag for <paramref name="context"/>.</summary>
    /// <param name="macKey">MacKey, taken from the start of the derived keying material.</param>
    /// <param name="context">The MacData inputs.</param>
    /// <param name="mac">The MAC function.</param>
    /// <param name="tagLength">MacTagLen: at least 64 bits and at most the MAC output length.</param>
    /// <param name="strength">The target security strength; MacKey must be at least this long (Table 5).</param>
    public static byte[] GenerateTag(
        ReadOnlySpan<byte> macKey,
        KeyConfirmationContext context,
        KeyConfirmationMac mac,
        BitLength tagLength,
        SecurityStrength strength)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(mac);
        Validate(macKey, mac, tagLength, strength);
        byte[] data = context.EncodeMacData();
        byte[] full = mac.Kmac is { } kmac
            ? Macs.Kmac(Sp800108.Strength(kmac), macKey, data, KmacCustomization, tagLength.Bits)
            : Macs.Compute(mac.Prf!, macKey, data);
        try
        {
            byte[] tag = full.AsSpan(0, tagLength.ByteLength).ToArray();
            Bits.MaskTail(tag, tagLength.Bits);
            return tag;
        }
        finally
        {
            Array.Clear(full);
        }
    }

    /// <summary>Recomputes the tag and compares it with <paramref name="receivedTag"/> in constant time.</summary>
    public static bool VerifyTag(
        ReadOnlySpan<byte> receivedTag,
        ReadOnlySpan<byte> macKey,
        KeyConfirmationContext context,
        KeyConfirmationMac mac,
        BitLength tagLength,
        SecurityStrength strength)
    {
        byte[] expected = GenerateTag(macKey, context, mac, tagLength, strength);
        try
        {
            return Arrays.FixedTimeEquals(expected, receivedTag.ToArray());
        }
        finally
        {
            Array.Clear(expected);
        }
    }

    private static void Validate(ReadOnlySpan<byte> key, KeyConfirmationMac mac, BitLength tagLength, SecurityStrength strength)
    {
        if (tagLength.Bits < 64 || tagLength.Bits > mac.MaxTagBits)
            throw new KdfParameterException($"MacTagLen must be between 64 bits and the {mac} output length.", nameof(tagLength));
        int keyBits = key.Length * 8;
        if (mac.Prf is { IsCmac: true } cmac)
        {
            // Macs.Create enforces the exact AES key length.
            if (strength.Bits > cmac.AesKeyBits)
                throw new KdfParameterException($"{cmac} cannot support {strength} security.", nameof(strength));
            return;
        }

        if (mac.Kmac is { } kmac && strength.Bits > Sp800108.Strength(kmac))
            throw new KdfParameterException($"{kmac} cannot support {strength} security.", nameof(strength));
        // Table 5: HMAC and KMAC keys are between the security strength and 512 bits.
        if (keyBits < strength.Bits || keyBits > 512)
            throw new KdfParameterException($"{mac} MacKey must be between {strength.Bits} and 512 bits.", nameof(key));
    }
}
