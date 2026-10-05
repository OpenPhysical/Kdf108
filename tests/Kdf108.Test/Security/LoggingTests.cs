using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;

namespace Kdf108.Test.Security;

/// <summary>Every service logs what it did through the container's logging, and never logs a secret.</summary>
[TestFixture]
public sealed class LoggingTests
{
    [Test]
    public void ServicesLogAlgorithmsAndLengthsButNoSecrets()
    {
        using var provider = new ServiceCollection()
            .AddLogging(logging => logging.SetMinimumLevel(LogLevel.Trace).AddFakeLogging())
            .AddKdf108()
            .BuildServiceProvider();
        var secrets = new List<byte[]>();
        byte[] Track(byte[] value) { secrets.Add(value); return value; }

        var kdf = provider.GetRequiredService<ISp800108Kdf>();
        var c = provider.GetRequiredService<ISp80056CKdf>();
        var ecc = provider.GetRequiredService<IEcKeyAgreement>();
        var ffc = provider.GetRequiredService<IFfcKeyAgreement>();
        var kc = provider.GetRequiredService<IKeyConfirmation>();

        byte[] key = Track(Convert.FromHexString("0F1E2D3C4B5A69788796A5B4C3D2E1F0"));
        var length = BitLength.Create(256);
        Track(kdf.Derive(key, Prf.Hmac(NistHashAlgorithm.Sha256), "label"u8, "context"u8, length));
        Track(kdf.DeriveKmac(key, KmacVariant.Kmac128, "label"u8, "context"u8, length));

        var p256 = EcDomain.Named(EcCurve.P256);
        var u = EcEphemeralKeyPair.Generate(p256);
        Track(u.ExportPrivate());
        byte[] z = Track(ecc.Ephemeral(u, EcEphemeralKeyPair.Generate(p256).PublicKey));
        var group = FfcDomain.Named(FfcSafePrimeGroup.Ffdhe2048);
        Track(ffc.Ephemeral(FfcEphemeralKeyPair.Generate(group), FfcEphemeralKeyPair.Generate(group).PublicKey));

        Track(c.OneStep(z, OneStepFunction.HashFunction(NistHashAlgorithm.Sha256), "info"u8, length, SecurityStrength.Bits128));
        Track(c.TwoStep(z, Extraction.Hmac(NistHashAlgorithm.Sha256), KeyExpansion.Counter("info"u8), length, SecurityStrength.Bits128));
        var context = new KeyConfirmationContext(KeyConfirmationMode.Unilateral, Party.U, "U"u8, "V"u8, default, default);
        var mac = KeyConfirmationMac.Hmac(NistHashAlgorithm.Sha256);
        byte[] tag = Track(kc.GenerateTag(key, context, mac, BitLength.Create(128), SecurityStrength.Bits128));
        Assert.That(kc.VerifyTag(new byte[16], key, context, mac, BitLength.Create(128), SecurityStrength.Bits128), Is.False);
        Assert.Throws<KdfParameterException>(() => kdf.Derive(new byte[15], Prf.AesCmac(128), "l"u8, "c"u8, length));
        Assert.Throws<InvalidKeyException>(() => ecc.Ephemeral(u, EcEphemeralKeyPair.Generate(EcDomain.Named(EcCurve.P384)).PublicKey));

        var records = provider.GetFakeLogCollector().GetSnapshot();
        Assert.That(records.Count(r => r.Level == LogLevel.Debug), Is.EqualTo(7));
        Assert.That(records.Where(r => r.Level == LogLevel.Warning).Select(r => r.Id.Id), Is.EquivalentTo(new[] { 3, 2, 2 }));
        Assert.That(records.Select(r => r.Category).Distinct(), Is.SupersetOf(new[] { typeof(Sp800108Kdf).FullName, typeof(EcKeyAgreement).FullName }));

        string everything = string.Join("\n", records.Select(r => r.Message));
        foreach (byte[] secret in secrets.Append(tag))
        {
            Assert.That(everything, Does.Not.Contain(Convert.ToHexString(secret.AsSpan(0, Math.Min(8, secret.Length)))).IgnoreCase, "A secret appeared in the log.");
            Assert.That(everything, Does.Not.Contain(Convert.ToBase64String(secret.AsSpan(0, Math.Min(6, secret.Length)))), "A secret appeared in the log.");
        }
    }
}
