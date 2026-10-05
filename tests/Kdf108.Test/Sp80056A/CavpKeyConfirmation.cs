// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only

using System;
using Kdf108.Domain.Sp80056A;
using Kdf108.Domain.Sp80056C;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Kdf108.Test.Sp80056A;

internal static class CavpKeyConfirmation
{
    internal static byte[] EncodeMacData(CavpTestVector vector) => CreateContext(vector).Encode();

    internal static byte[] GenerateProductionTag(CavpTestVector vector, byte[] key)
    {
        if (vector.CAVSTag is null) throw new InvalidOperationException("CAVP key-confirmation vector has no tag.");
        var algorithm = CreateProductionAlgorithm(vector);
        if (algorithm is null)
            return GenerateLegacyCcmTag(vector, key, EncodeMacData(vector));
        return Sp80056AKeyConfirmation.GenerateTag(
            key, CreateContext(vector), algorithm, BitLength.Create(vector.CAVSTag.Length * 8L), SecurityStrength.Bits112);
    }

    internal static bool VerifyProductionTag(CavpTestVector vector, byte[] key, byte[] expectedTag)
    {
        var algorithm = CreateProductionAlgorithm(vector);
        if (algorithm is not null)
        {
            return Sp80056AKeyConfirmation.VerifyTag(
                expectedTag, key, CreateContext(vector), algorithm,
                BitLength.Create(expectedTag.Length * 8L), SecurityStrength.Bits112);
        }

        byte[] actual = GenerateLegacyCcmTag(vector, key, EncodeMacData(vector));
        return Arrays.FixedTimeEquals(expectedTag, actual);
    }

    internal static byte[] GenerateTagOverEncodedData(CavpTestVector vector, byte[] key, byte[] encodedData)
    {
        if (vector.CAVSTag is null) throw new InvalidOperationException("CAVP key-confirmation vector has no tag.");
        if (vector.MacVariant?.StartsWith("CCM ", StringComparison.Ordinal) == true)
            return GenerateLegacyCcmTag(vector, key, encodedData);

        IMac mac = vector.MacVariant?.StartsWith("CMAC ", StringComparison.Ordinal) == true
            ? new CMac(new AesEngine())
            : new HMac(Sp80056COneStep.CreateDigest(ParseHash(vector.MacVariant)));
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(encodedData, 0, encodedData.Length);
        var full = new byte[mac.GetMacSize()];
        mac.DoFinal(full, 0);
        return full.AsSpan(0, vector.CAVSTag.Length).ToArray();
    }

    private static KeyConfirmationContext CreateContext(CavpTestVector vector)
    {
        string name = System.IO.Path.GetFileNameWithoutExtension(vector.Source.FilePath);
        bool iutIsU = vector.Source.Role == "initiator";
        bool iutProvides = name.Contains("_prov_", StringComparison.Ordinal);
        bool bilateral = name.Contains("_blat", StringComparison.Ordinal);
        byte[] iutId = Convert.FromHexString("a1b2c3d4e5");
        byte[] cavsId = "CAVSid"u8.ToArray();
        byte[] iutEphemeralData = GetEphemeralData(vector, "IUT");
        byte[] cavsEphemeralData = GetEphemeralData(vector, "CAVS");
        return new KeyConfirmationContext(
            bilateral ? KeyConfirmationMode.Bilateral : KeyConfirmationMode.Unilateral,
            iutProvides == iutIsU ? KeyConfirmationParty.PartyU : KeyConfirmationParty.PartyV,
            iutIsU ? iutId : cavsId,
            iutIsU ? cavsId : iutId,
            iutIsU ? iutEphemeralData : cavsEphemeralData,
            iutIsU ? cavsEphemeralData : iutEphemeralData);
    }

    private static KeyConfirmationAlgorithm? CreateProductionAlgorithm(CavpTestVector vector)
    {
        string variant = vector.MacVariant ?? throw new InvalidOperationException("Missing MAC variant metadata.");
        if (variant.StartsWith("CCM ", StringComparison.Ordinal)) return null;
        if (variant.StartsWith("CMAC ", StringComparison.Ordinal))
            return KeyConfirmationAlgorithm.AesCmacFunction(ParseTrailingBits(variant));
        if (variant.StartsWith("HMAC ", StringComparison.Ordinal))
            return KeyConfirmationAlgorithm.HmacFunction(ParseHash(variant));
        throw new InvalidOperationException($"Unsupported CAVP MAC variant '{variant}'.");
    }

    private static NistHashAlgorithm ParseHash(string? value) => value switch
    {
        not null when value.Contains("SHA224", StringComparison.Ordinal) => NistHashAlgorithm.Sha224,
        not null when value.Contains("SHA256", StringComparison.Ordinal) => NistHashAlgorithm.Sha256,
        not null when value.Contains("SHA384", StringComparison.Ordinal) => NistHashAlgorithm.Sha384,
        not null when value.Contains("SHA512", StringComparison.Ordinal) => NistHashAlgorithm.Sha512,
        _ => throw new InvalidOperationException($"Unsupported CAVP hash metadata '{value}'.")
    };

    private static int ParseTrailingBits(string value) =>
        value.EndsWith("128", StringComparison.Ordinal) ? 128 :
        value.EndsWith("192", StringComparison.Ordinal) ? 192 :
        value.EndsWith("256", StringComparison.Ordinal) ? 256 :
        throw new InvalidOperationException($"Unsupported CAVP AES variant '{value}'.");

    // CCM was present in the 2016 legacy corpus but is not a Rev. 3 production API option.
    private static byte[] GenerateLegacyCcmTag(CavpTestVector vector, byte[] key, byte[] associatedData)
    {
        byte[] nonce = GetHex(vector, "CCMNonce");
        var cipher = new CcmBlockCipher(new AesEngine());
        cipher.Init(true, new AeadParameters(new KeyParameter(key), vector.CAVSTag!.Length * 8, nonce, associatedData));
        var output = new byte[cipher.GetOutputSize(0)];
        int length = cipher.DoFinal(output, 0);
        return output.AsSpan(0, length).ToArray();
    }

    private static byte[] GetHex(CavpTestVector vector, string name) =>
        vector.Fields.TryGetValue(name, out string? value)
            ? Convert.FromHexString(value)
            : throw new InvalidOperationException($"Vector {vector.Count} is missing {name}.");

    private static byte[] GetEphemeralData(CavpTestVector vector, string party)
    {
        // EphemData is the party's ephemeral public key when the scheme has one.
        // Otherwise CAVS supplies the nonce that substitutes for that public key.
        string xName = $"Qe{party}x";
        string yName = $"Qe{party}y";
        if (vector.Fields.TryGetValue(xName, out string? x) &&
            vector.Fields.TryGetValue(yName, out string? y))
            return Convert.FromHexString(x + y);

        foreach (string name in new[] { $"Yephem{party}", $"NonceEphem{party}", $"NonceDKM{party}" })
            if (vector.Fields.TryGetValue(name, out string? value))
                return Convert.FromHexString(value);

        // A party in a static or one-flow scheme may contribute neither an
        // ephemeral public key nor a replacement nonce. Its EphemData is empty.
        return Array.Empty<byte>();
    }
}
