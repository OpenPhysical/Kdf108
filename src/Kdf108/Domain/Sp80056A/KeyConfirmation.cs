// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#pragma warning disable CS1591

using System;
using System.Text;
using Kdf108.Domain.Sp80056C;
using Kdf108.Internal;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Kdf108.Domain.Sp80056A;

public enum KeyConfirmationParty { PartyU, PartyV }
public enum KeyConfirmationMode { Unilateral, Bilateral }

public abstract class KeyConfirmationAlgorithm
{
    private KeyConfirmationAlgorithm() { }

    public sealed class Hmac : KeyConfirmationAlgorithm
    {
        internal Hmac(NistHashAlgorithm hash) => Hash = hash;
        public NistHashAlgorithm Hash { get; }
    }

    public sealed class Kmac : KeyConfirmationAlgorithm
    {
        internal Kmac(int strength, BitLength outputLength) { Strength = strength; OutputLength = outputLength; }
        public int Strength { get; }
        public BitLength OutputLength { get; }
    }

    public sealed class AesCmac : KeyConfirmationAlgorithm
    {
        internal AesCmac(int keyBits) => KeyBits = keyBits;
        public int KeyBits { get; }
    }

    public static KeyConfirmationAlgorithm HmacFunction(NistHashAlgorithm hash) => new Hmac(hash);
    public static KeyConfirmationAlgorithm Kmac128(BitLength outputLength) => new Kmac(128, outputLength);
    public static KeyConfirmationAlgorithm Kmac256(BitLength outputLength) => new Kmac(256, outputLength);
    public static KeyConfirmationAlgorithm AesCmacFunction(int keyBits)
    {
        if (keyBits is not (128 or 192 or 256))
            throw new ArgumentOutOfRangeException(nameof(keyBits));
        return new AesCmac(keyBits);
    }
}

/// <summary>The agreed byte-string components of SP 800-56A key-confirmation MacData.</summary>
public sealed class KeyConfirmationContext
{
    private readonly byte[] _partyUId;
    private readonly byte[] _partyVId;
    private readonly byte[] _partyUEphemeralData;
    private readonly byte[] _partyVEphemeralData;
    private readonly byte[] _text;

    public KeyConfirmationContext(
        KeyConfirmationMode mode,
        KeyConfirmationParty provider,
        ReadOnlySpan<byte> partyUId,
        ReadOnlySpan<byte> partyVId,
        ReadOnlySpan<byte> partyUEphemeralData,
        ReadOnlySpan<byte> partyVEphemeralData,
        ReadOnlySpan<byte> text = default)
    {
        if (partyUId.IsEmpty) throw new ArgumentException("Party U identifier must not be empty.", nameof(partyUId));
        if (partyVId.IsEmpty) throw new ArgumentException("Party V identifier must not be empty.", nameof(partyVId));
        Mode = mode;
        Provider = provider;
        _partyUId = partyUId.ToArray();
        _partyVId = partyVId.ToArray();
        _partyUEphemeralData = partyUEphemeralData.ToArray();
        _partyVEphemeralData = partyVEphemeralData.ToArray();
        _text = text.ToArray();
    }

    public KeyConfirmationMode Mode { get; }
    public KeyConfirmationParty Provider { get; }

    internal byte[] Encode()
    {
        string marker = (Mode, Provider) switch
        {
            (KeyConfirmationMode.Unilateral, KeyConfirmationParty.PartyU) => "KC_1_U",
            (KeyConfirmationMode.Unilateral, KeyConfirmationParty.PartyV) => "KC_1_V",
            (KeyConfirmationMode.Bilateral, KeyConfirmationParty.PartyU) => "KC_2_U",
            (KeyConfirmationMode.Bilateral, KeyConfirmationParty.PartyV) => "KC_2_V",
            _ => throw new ArgumentOutOfRangeException()
        };

        var message = Encoding.ASCII.GetBytes(marker);
        var providerId = Provider == KeyConfirmationParty.PartyU ? _partyUId : _partyVId;
        var recipientId = Provider == KeyConfirmationParty.PartyU ? _partyVId : _partyUId;
        var providerEphemeral = Provider == KeyConfirmationParty.PartyU ? _partyUEphemeralData : _partyVEphemeralData;
        var recipientEphemeral = Provider == KeyConfirmationParty.PartyU ? _partyVEphemeralData : _partyUEphemeralData;
        var output = new byte[checked(message.Length + providerId.Length + recipientId.Length +
            providerEphemeral.Length + recipientEphemeral.Length + _text.Length)];
        int offset = 0;
        Copy(message);
        Copy(providerId);
        Copy(recipientId);
        Copy(providerEphemeral);
        Copy(recipientEphemeral);
        Copy(_text);
        return output;

        void Copy(byte[] component)
        {
            component.CopyTo(output, offset);
            offset += component.Length;
        }
    }
}

public static class Sp80056AKeyConfirmation
{
    private static readonly byte[] KmacCustomization = Array.Empty<byte>();

    public static byte[] GenerateTag(
        ReadOnlySpan<byte> macKey,
        KeyConfirmationContext context,
        KeyConfirmationAlgorithm algorithm,
        BitLength tagLength,
        SecurityStrength securityStrength)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(algorithm);
        if (macKey.IsEmpty) throw new ArgumentException("MAC key must not be empty.", nameof(macKey));

        int outputBits = GetOutputBits(algorithm);
        if (tagLength.Bits < 64 || tagLength.Bits > outputBits)
            throw new ArgumentOutOfRangeException(nameof(tagLength), "MAC tag length must be between 64 bits and the MAC output length.");
        ValidateKey(macKey, algorithm, securityStrength);

        var data = context.Encode();
        var key = macKey.ToArray();
        try
        {
            byte[] fullTag = algorithm switch
            {
                KeyConfirmationAlgorithm.Hmac hmac => ComputeHmac(key, data, hmac.Hash),
                KeyConfirmationAlgorithm.Kmac kmac => ComputeKmac(key, data, kmac),
                KeyConfirmationAlgorithm.AesCmac => ComputeCmac(key, data),
                _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
            };
            try
            {
                var tag = fullTag.AsSpan(0, tagLength.ByteLength).ToArray();
                int remainder = (int)(tagLength.Bits & 7);
                if (remainder != 0) tag[^1] &= (byte)(0xFF << (8 - remainder));
                return tag;
            }
            finally { SecureMemory.Clear(fullTag); }
        }
        finally
        {
            SecureMemory.Clear(key);
            SecureMemory.Clear(data);
        }
    }

    public static bool VerifyTag(ReadOnlySpan<byte> expectedTag, ReadOnlySpan<byte> macKey, KeyConfirmationContext context, KeyConfirmationAlgorithm algorithm, BitLength tagLength, SecurityStrength securityStrength)
    {
        var actual = GenerateTag(macKey, context, algorithm, tagLength, securityStrength);
        try { return Arrays.FixedTimeEquals(expectedTag.ToArray(), actual); }
        finally { SecureMemory.Clear(actual); }
    }

    private static byte[] ComputeHmac(byte[] key, byte[] data, NistHashAlgorithm hash)
    {
        var hmac = new HMac(Sp80056COneStep.CreateDigest(hash));
        hmac.Init(new KeyParameter(key));
        hmac.BlockUpdate(data, 0, data.Length);
        var output = new byte[hmac.GetMacSize()];
        hmac.DoFinal(output, 0);
        return output;
    }

    private static byte[] ComputeKmac(byte[] key, byte[] data, KeyConfirmationAlgorithm.Kmac function)
    {
        var kmac = new KMac(function.Strength, KmacCustomization);
        kmac.Init(new KeyParameter(key));
        kmac.BlockUpdate(data, 0, data.Length);
        var output = new byte[function.OutputLength.ByteLength];
        kmac.OutputFinal(output, 0, output.Length);
        return output;
    }

    private static byte[] ComputeCmac(byte[] key, byte[] data)
    {
        var cmac = new CMac(new AesEngine());
        cmac.Init(new KeyParameter(key));
        cmac.BlockUpdate(data, 0, data.Length);
        var output = new byte[cmac.GetMacSize()];
        cmac.DoFinal(output, 0);
        return output;
    }

    private static int GetOutputBits(KeyConfirmationAlgorithm algorithm) => algorithm switch
    {
        KeyConfirmationAlgorithm.Hmac hmac => Sp80056CAlgorithmInfo.OutputBits(hmac.Hash),
        KeyConfirmationAlgorithm.Kmac kmac => checked((int)kmac.OutputLength.Bits),
        KeyConfirmationAlgorithm.AesCmac => 128,
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm))
    };

    private static void ValidateKey(ReadOnlySpan<byte> key, KeyConfirmationAlgorithm algorithm, SecurityStrength strength)
    {
        int keyBits = checked(key.Length * 8);
        switch (algorithm)
        {
            case KeyConfirmationAlgorithm.Hmac:
                if (keyBits < strength.Bits || keyBits > 512)
                    throw new ArgumentException("HMAC key length must support the target strength and be at most 512 bits.", nameof(key));
                break;
            case KeyConfirmationAlgorithm.Kmac kmac:
                if (strength.Bits > kmac.Strength)
                    throw new ArgumentException("KMAC variant does not support the requested security strength.", nameof(strength));
                if (keyBits < strength.Bits || keyBits > 512)
                    throw new ArgumentException("KMAC key length must support the target strength and be at most 512 bits.", nameof(key));
                break;
            case KeyConfirmationAlgorithm.AesCmac cmac when keyBits != cmac.KeyBits:
                throw new ArgumentException("AES-CMAC key length must equal the selected AES key size.", nameof(key));
            case KeyConfirmationAlgorithm.AesCmac cmac when strength.Bits > cmac.KeyBits:
                throw new ArgumentException("AES-CMAC cannot support the requested security strength.", nameof(strength));
        }
    }
}
