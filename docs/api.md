# API guide

Kdf108 has one shape throughout:

- **Static classes** do the work: `Sp800108`, `Sp80056C`, `EcSchemes`, `FfcSchemes`, and
  `KeyConfirmation`. They are pure functions with no state and no I/O.
- **Services** (`ISp800108Kdf`, `ISp80056CKdf`, `IEcKeyAgreement`, `IFfcKeyAgreement`,
  `IKeyConfirmation`) mirror them method for method and add logging. Register them with
  `services.AddKdf108()` or construct them directly.
- **Secrets go in as spans and come out as new arrays.** You own every array you get back; clear
  it with `Array.Clear` when you are done. Nothing in the library needs disposing.
- **Lengths are always `BitLength`**, never a bare number of bytes or bits.
- **Algorithms are small immutable values**: `Prf`, `KeyExpansion`, `OneStepFunction`,
  `Extraction`, and `KeyConfirmationMac`. Invalid combinations are rejected when you create them.
- **Every failure is a `Kdf108Exception`**: `KdfParameterException` for a parameter the standard
  does not allow, `InvalidKeyException` for a key or domain that fails validation, and
  `KeyAgreementException` for a forbidden shared secret.

## SP 800-108: keys from a key

`Sp800108.Derive(key, prf, label, context, length)` is counter mode with a 32-bit counter and
the conventional fixed input `Label || 0x00 || Context || [L]32`. It is the right choice for
most applications.

For anything else, describe the expansion with `KeyExpansion`:

<!-- snippet: sp800108-modes -->
```csharp
var length = BitLength.Create(512);
byte[] fixedInput = Sp800108.FixedInput("session"u8, "client-7"u8, length); // Label || 0x00 || Context || [L]32

byte[] counter = Sp800108.Derive(kdk, Prf.AesCmac(256), KeyExpansion.Counter(fixedInput, counterBits: 16), length);
byte[] feedback = Sp800108.Derive(kdk, Prf.Hmac(NistHashAlgorithm.Sha384), KeyExpansion.Feedback(fixedInput, iv), length);
byte[] pipeline = Sp800108.Derive(kdk, Prf.Hmac(NistHashAlgorithm.Sha3_256), KeyExpansion.DoublePipeline(fixedInput, useCounter: false), length);
byte[] kmac = Sp800108.DeriveKmac(kdk, KmacVariant.Kmac256, label: "session"u8, context: "client-7"u8, length);
```

| Mode | Factory | Counter positions |
|---|---|---|
| Counter (§4.1) | `KeyExpansion.Counter`, `KeyExpansion.CounterInMiddle` | before or after the fixed input, or in the middle |
| Feedback (§4.2) | `KeyExpansion.Feedback` | after K(i-1) (the §4.2 form), before it, or after the fixed input; or no counter |
| Double pipeline (§4.3) | `KeyExpansion.DoublePipeline` | after A(i) (the §4.3 form), before it, or after the fixed input; or no counter |
| KMAC (§4.4) | `Sp800108.DeriveKmac` | none (one KMAC call) |

The counter width r is 8, 16, 24, or 32 bits. PRFs are HMAC with any approved hash (SHA-1,
SHA-2, SHA-512/t, SHA-3) or AES-CMAC with a 128-, 192-, or 256-bit key. TDEA is not available:
SP 800-131A disallows it.

## SP 800-56A: agreeing on a shared secret

Start from a domain: `EcDomain.Named(EcCurve.P256)` for one of the twelve NIST curves, or
`FfcDomain.Named(FfcSafePrimeGroup.Ffdhe3072)` for a safe-prime group. Keys come in four types per
family (static or ephemeral, public key or key pair), so a scheme cannot be given the wrong kind.

<!-- snippet: importing-keys -->
```csharp
var p384 = EcDomain.Named(EcCurve.P384);
var theirKey = EcStaticPublicKey.Import(p384, publicKey);              // full §5.6.2.3.3 validation
var myPair = EcStaticKeyPair.Import(p384, privateKey, publicKey);      // also checks the halves match

var fips186 = FfcDomain.ImportFips186(p, q, g, FfcDomainAssurance.TrustedAuthority("Our CA policy 4.2"));
```

Importing a public key runs full validation (§5.6.2.3). `KeyPair.Import` also checks that the
private and public halves belong together. FIPS 186-type finite-field parameters need assurance:
either replay of their FIPS 186-4 generation evidence (`FfcDomainAssurance.Fips186Evidence`) or
a named trusted authority.

`EcSchemes` and `FfcSchemes` have the same methods:

| Method | SP 800-56A scheme (ECC / FFC) | Z |
|---|---|---|
| `Ephemeral` | Ephemeral Unified / dhEphem | CDH(ephemeral, ephemeral) |
| `Static` | Static Unified / dhStatic | CDH(static, static) |
| `OneFlowAsPartyU`, `OneFlowAsPartyV` | One-Pass DH / dhOneFlow | CDH(U ephemeral, V static) |
| `Hybrid` | Full Unified / dhHybrid1 | Ze \|\| Zs |
| `HybridOneFlowAsPartyU`, `...AsPartyV` | One-Pass Unified / dhHybridOneFlow | Ze \|\| Zs |
| `Mqv2` | Full MQV / MQV2 | MQV |
| `Mqv1AsPartyU`, `Mqv1AsPartyV` | One-Pass MQV / MQV1 | MQV |

Party U is the initiator and V the responder. Static keys authenticate the parties; the purely
ephemeral scheme needs authentication from somewhere else, such as signatures.

## SP 800-56C: keys from a shared secret

`Sp80056C.OneStep(z, function, fixedInfo, length, strength)` hashes `counter || Z || FixedInfo`
with a hash, HMAC, or KMAC (`OneStepFunction`). The two-step method extracts a key-derivation key
with HMAC or AES-CMAC and expands it with SP 800-108. To derive several keys from one Z, extract
once and expand once per key with distinct fixed input:

<!-- snippet: two-step -->
```csharp
byte[] z = FfcSchemes.Mqv2(myStatic, myEphemeral, theirStatic, theirEphemeral);

// Extract once, then expand one key per purpose with distinct fixed input.
var extraction = Extraction.Hmac(NistHashAlgorithm.Sha256, salt: "protocol v1 salt"u8);
byte[] kdk = Sp80056C.Extract(z, extraction, SecurityStrength.Bits128);
var length = BitLength.Create(256);
byte[] encryptionKey = Sp800108.Derive(kdk, extraction.ExpansionPrf, "encrypt"u8, fixedInfo, length);
byte[] macKey = Sp800108.Derive(kdk, extraction.ExpansionPrf, "mac"u8, fixedInfo, length);
Array.Clear(z);
Array.Clear(kdk);
```

`Extraction.ExpansionPrf` is the PRF the standard requires for expansion: the same HMAC, or
AES-128-CMAC after AES-CMAC extraction. The security strength you pass is checked against the
function you chose.

## Key confirmation

After both sides derive keying material, its first bits can serve as MacKey to prove that both
derived the same thing (§5.9):

<!-- snippet: key-confirmation -->
```csharp
var mac = KeyConfirmationMac.Hmac(NistHashAlgorithm.Sha256);
var tagLength = BitLength.Create(128);

// Bob (party V) proves he derived the same MacKey. Alice (party U) checks the tag.
var fromBob = new KeyConfirmationContext(KeyConfirmationMode.Bilateral, provider: Party.V,
    partyUId: "alice"u8, partyVId: "bob"u8, alicePublic, bobPublic);
byte[] tag = KeyConfirmation.GenerateTag(macKey, fromBob, mac, tagLength, SecurityStrength.Bits128);
bool confirmed = KeyConfirmation.VerifyTag(tag, macKey, fromBob, mac, tagLength, SecurityStrength.Bits128);
```

The MAC is HMAC, AES-CMAC, or KMAC (with customization string "KC"). Tags are 64 bits up to the
MAC's output length and are compared in constant time.

## Errors

<!-- snippet: errors -->
```csharp
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
```

## Dependency injection and logging

<!-- snippet: dependency-injection -->
```csharp
builder.Services.AddKdf108(); // ISp800108Kdf, ISp80056CKdf, IEcKeyAgreement, IFfcKeyAgreement, IKeyConfirmation
```

<!-- snippet: dependency-injection-consumer -->
```csharp
public sealed class SessionKeys(ISp800108Kdf kdf)
{
    public byte[] ForTenant(ReadOnlySpan<byte> keyDerivationKey, int tenant) =>
        kdf.Derive(keyDerivationKey, Prf.Hmac(NistHashAlgorithm.Sha256),
            label: "session"u8, context: Encoding.UTF8.GetBytes($"tenant:{tenant}"), BitLength.Create(256));
}
```

Services log each operation at Debug (algorithm and output length) and each rejection at Warning
(the reason), with stable event IDs: 1 for a completed operation, 2 for a rejection, 3 for a
key-confirmation tag mismatch. Keys, shared secrets, and derived output are never logged.
