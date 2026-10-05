using System;
using System.Linq;
using System.Text;
using Microsoft.Extensions.DependencyInjection;

namespace Kdf108.Test.Docs;

/// <summary>
/// The source of every C# code block in README.md and docs/. Each <c>#region snippet:</c> is
/// copied verbatim into the markdown; <see cref="DocSnippetTests"/> fails if they drift.
/// </summary>
[TestFixture]
public class Snippets
{
    [Test]
    public void QuickStartSp800108()
    {
        byte[] keyDerivationKey = new byte[32]; // from your key store; at least 128 random bits
        #region snippet:quickstart-sp800108
        byte[] key = Sp800108.Derive(
            keyDerivationKey,
            Prf.Hmac(NistHashAlgorithm.Sha256),
            label: "file-encryption"u8,
            context: "tenant:42"u8,
            BitLength.Create(256));
        #endregion
        Assert.That(key, Has.Length.EqualTo(32));
    }

    [Test]
    public void QuickStartKeyAgreement()
    {
        #region snippet:quickstart-agreement
        var curve = EcDomain.Named(EcCurve.P256);

        // Each party generates an ephemeral key pair and sends the other its public key.
        var alice = EcEphemeralKeyPair.Generate(curve);
        var bob = EcEphemeralKeyPair.Generate(curve);
        byte[] alicePublic = alice.PublicKey.Export();

        // Bob validates Alice's key on import, then computes Z and derives a key from it.
        var fromAlice = EcEphemeralPublicKey.Import(curve, alicePublic);
        byte[] z = EcSchemes.Ephemeral(bob, fromAlice);
        byte[] key = Sp80056C.OneStep(
            z,
            OneStepFunction.HashFunction(NistHashAlgorithm.Sha256),
            fixedInfo: "my-protocol v1|alice|bob"u8,
            BitLength.Create(256),
            SecurityStrength.Bits128);
        Array.Clear(z);
        #endregion
        Assert.That(key, Is.EqualTo(Sp80056C.OneStep(EcSchemes.Ephemeral(alice, bob.PublicKey),
            OneStepFunction.HashFunction(NistHashAlgorithm.Sha256), "my-protocol v1|alice|bob"u8, BitLength.Create(256), SecurityStrength.Bits128)));
    }

    [Test]
    public void Sp800108Modes()
    {
        byte[] kdk = new byte[32];
        byte[] iv = new byte[16];
        #region snippet:sp800108-modes
        var length = BitLength.Create(512);
        byte[] fixedInput = Sp800108.FixedInput("session"u8, "client-7"u8, length); // Label || 0x00 || Context || [L]32

        byte[] counter = Sp800108.Derive(kdk, Prf.AesCmac(256), KeyExpansion.Counter(fixedInput, counterBits: 16), length);
        byte[] feedback = Sp800108.Derive(kdk, Prf.Hmac(NistHashAlgorithm.Sha384), KeyExpansion.Feedback(fixedInput, iv), length);
        byte[] pipeline = Sp800108.Derive(kdk, Prf.Hmac(NistHashAlgorithm.Sha3_256), KeyExpansion.DoublePipeline(fixedInput, useCounter: false), length);
        byte[] kmac = Sp800108.DeriveKmac(kdk, KmacVariant.Kmac256, label: "session"u8, context: "client-7"u8, length);
        #endregion
        Assert.That(new[] { counter, feedback, pipeline, kmac }, Has.All.Length.EqualTo(64));
    }

    [Test]
    public void TwoStepManyKeys()
    {
        var group = FfcDomain.Named(FfcSafePrimeGroup.Ffdhe3072);
        var uS = FfcStaticKeyPair.Generate(group);
        var uE = FfcEphemeralKeyPair.Generate(group);
        var vS = FfcStaticKeyPair.Generate(group);
        var vE = FfcEphemeralKeyPair.Generate(group);
        FfcStaticKeyPair myStatic = uS;
        FfcEphemeralKeyPair myEphemeral = uE;
        FfcStaticPublicKey theirStatic = vS.PublicKey;
        FfcEphemeralPublicKey theirEphemeral = vE.PublicKey;
        byte[] fixedInfo = "protocol v1|U|V"u8.ToArray();
        #region snippet:two-step
        byte[] z = FfcSchemes.Mqv2(myStatic, myEphemeral, theirStatic, theirEphemeral);

        // Extract once, then expand one key per purpose with distinct fixed input.
        var extraction = Extraction.Hmac(NistHashAlgorithm.Sha256, salt: "protocol v1 salt"u8);
        byte[] kdk = Sp80056C.Extract(z, extraction, SecurityStrength.Bits128);
        var length = BitLength.Create(256);
        byte[] encryptionKey = Sp800108.Derive(kdk, extraction.ExpansionPrf, "encrypt"u8, fixedInfo, length);
        byte[] macKey = Sp800108.Derive(kdk, extraction.ExpansionPrf, "mac"u8, fixedInfo, length);
        Array.Clear(z);
        Array.Clear(kdk);
        #endregion
        Assert.That(encryptionKey, Is.Not.EqualTo(macKey));
    }

    [Test]
    public void KeyConfirmationRoundTrip()
    {
        byte[] macKey = new byte[32];
        byte[] alicePublic = new byte[65];
        byte[] bobPublic = new byte[65];
        #region snippet:key-confirmation
        var mac = KeyConfirmationMac.Hmac(NistHashAlgorithm.Sha256);
        var tagLength = BitLength.Create(128);

        // Bob (party V) proves he derived the same MacKey. Alice (party U) checks the tag.
        var fromBob = new KeyConfirmationContext(KeyConfirmationMode.Bilateral, provider: Party.V,
            partyUId: "alice"u8, partyVId: "bob"u8, alicePublic, bobPublic);
        byte[] tag = KeyConfirmation.GenerateTag(macKey, fromBob, mac, tagLength, SecurityStrength.Bits128);
        bool confirmed = KeyConfirmation.VerifyTag(tag, macKey, fromBob, mac, tagLength, SecurityStrength.Bits128);
        #endregion
        Assert.That(confirmed, Is.True);
    }

    [Test]
    public void ImportingKeys()
    {
        var generated = EcStaticKeyPair.Generate(EcDomain.Named(EcCurve.P384));
        byte[] privateKey = generated.ExportPrivate();
        byte[] publicKey = generated.PublicKey.Export();
        byte[] p = FfcDomainHelpers.P, q = FfcDomainHelpers.Q, g = FfcDomainHelpers.G;
        #region snippet:importing-keys
        var p384 = EcDomain.Named(EcCurve.P384);
        var theirKey = EcStaticPublicKey.Import(p384, publicKey);              // full §5.6.2.3.3 validation
        var myPair = EcStaticKeyPair.Import(p384, privateKey, publicKey);      // also checks the halves match

        var fips186 = FfcDomain.ImportFips186(p, q, g, FfcDomainAssurance.TrustedAuthority("Our CA policy 4.2"));
        #endregion
        Assert.That(theirKey.Domain, Is.SameAs(myPair.Domain));
        Assert.That(fips186.ModulusBits, Is.EqualTo(2048));
    }

    [Test]
    public void DependencyInjection()
    {
        var builder = Microsoft.Extensions.Hosting.Host.CreateApplicationBuilder();
        #region snippet:dependency-injection
        builder.Services.AddKdf108(); // ISp800108Kdf, ISp80056CKdf, IEcKeyAgreement, IFfcKeyAgreement, IKeyConfirmation
        #endregion
        using var host = builder.Build();
        var keys = new SessionKeys(host.Services.GetRequiredService<ISp800108Kdf>());
        Assert.That(keys.ForTenant(new byte[32], 42), Has.Length.EqualTo(32));
    }

    #region snippet:dependency-injection-consumer
    public sealed class SessionKeys(ISp800108Kdf kdf)
    {
        public byte[] ForTenant(ReadOnlySpan<byte> keyDerivationKey, int tenant) =>
            kdf.Derive(keyDerivationKey, Prf.Hmac(NistHashAlgorithm.Sha256),
                label: "session"u8, context: Encoding.UTF8.GetBytes($"tenant:{tenant}"), BitLength.Create(256));
    }
    #endregion

    [Test]
    public void ErrorsAndLogging()
    {
        byte[] keyDerivationKey = new byte[15];
        string? reason = null;
        #region snippet:errors
        try
        {
            byte[] key = Sp800108.Derive(keyDerivationKey, Prf.AesCmac(128), "label"u8, "context"u8, BitLength.Create(128));
        }
        catch (InvalidKeyException e) when (e.Failure == KeyFailure.InvalidPublicKey)
        {
            reason = "the peer sent an invalid public key";
        }
        catch (Kdf108Exception e)
        {
            reason = e.Message; // every library failure derives from Kdf108Exception
        }
        #endregion
        Assert.That(reason, Does.Contain("128-bit key"));
    }

    [Test]
    public void DomainSeparation()
    {
        #region snippet:length-prefixed
        // Datalen || Data for every field, so "ab" + "c" and "a" + "bc" can never collide.
        static byte[] Encode(params string[] fields)
        {
            var output = new System.IO.MemoryStream();
            foreach (string field in fields)
            {
                byte[] data = Encoding.UTF8.GetBytes(field);
                output.Write([(byte)(data.Length >> 24), (byte)(data.Length >> 16), (byte)(data.Length >> 8), (byte)data.Length]);
                output.Write(data);
            }
            return output.ToArray();
        }

        byte[] context = Encode("tenant", "42", "user", "1001");
        #endregion
        Assert.That(Encode("ab", "c"), Is.Not.EqualTo(Encode("a", "bc")));
        Assert.That(context, Has.Length.EqualTo(4 * 4 + 6 + 2 + 4 + 4));
    }
}

internal static class FfcDomainHelpers
{
    private static readonly Support.RspRecord Header = Support.RspReader.Read(Support.TestPaths.Vectors("SP800-56A", "KASTestVectorsFFC2016",
        "Key Confirmation", "FFC MQV1 Scheme", "KASValidityTest_FFCMQV1_KDFConcat_KC_resp_prov_ulat.fax")).First();
    internal static byte[] P => Convert.FromHexString(Header.Header("P")!);
    internal static byte[] Q => Convert.FromHexString(Header.Header("Q")!);
    internal static byte[] G => Convert.FromHexString(Header.Header("G")!);
}
