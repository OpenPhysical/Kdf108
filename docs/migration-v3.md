# Migrating to 3.0

Version 3 replaces the whole public surface with one consistent API. Everything now lives in the
`Kdf108` namespace. Nothing needs disposing, lengths are `BitLength`, and every failure is a
`Kdf108Exception`.

| 2.x | 3.0 |
|---|---|
| `KdfEngine`, `IKdfEngine`, `KdfFactory`, `IKdf`, `KdfEngineLegacy` | `Sp800108` (static) or `ISp800108Kdf` (DI) |
| `CounterModeKdf`, `FeedbackModeKdf`, `DoublePipelineKdf` | `Sp800108.Derive(key, prf, KeyExpansion.Counter/Feedback/DoublePipeline(...), length)` |
| `KdfOptions`, `KdfOptionsBuilder`, `KdfRequest`, `KdfMode`, `CounterLocation` | `KeyExpansion` factories with `CounterPosition` or `IterationCounterPosition` |
| `PrfType.HmacSha256`, `PrfType.CmacAes128` | `Prf.Hmac(NistHashAlgorithm.Sha256)`, `Prf.AesCmac(128)` |
| `string` label, `byte[]` context, `long` bits | `ReadOnlySpan<byte>` label and context, `BitLength` |
| `Sp800108Kmac.DeriveKey` | `Sp800108.DeriveKmac` |
| `Sp80056COneStep.Derive(new OneStepKdfRequest(...))` | `Sp80056C.OneStep(z, OneStepFunction..., fixedInfo, length, strength)` |
| `Sp80056CTwoStep.Derive(new TwoStepKdfRequest(...))` | `Sp80056C.TwoStep(...)`, or `Sp80056C.Extract` plus `Sp800108.Derive` per key |
| `OneStepAuxiliaryFunction`, `TwoStepExtraction` | `OneStepFunction`, `Extraction` |
| `Sp80056COneStepKdf`, `Sp80056CTwoStepKdf`, `Sp80056COptions`, `ISp80056CKeyDerivationPipeline` | `Sp80056C` |
| `EcPrivateKey`, `EcPublicKey`, `EcKeyPair`, `CurveRegistry` (curve-name strings) | `EcDomain.Named(EcCurve...)`, `EcStatic/EphemeralPublicKey`, `EcStatic/EphemeralKeyPair` |
| `Sp80056AEcdhKeyAgreement`, `Sp80056APrivateKey`, `Sp80056APublicKey`, the validators | `EcSchemes` / `IEcKeyAgreement` |
| `EcdhKeyAgreement.Compute*`, `EcMqvKeyAgreement.Compute*` | `EcSchemes.Ephemeral`, `Static`, `Hybrid`, `OneFlowAsPartyU/V`, `HybridOneFlowAsPartyU/V`, `Mqv2`, `Mqv1AsPartyU/V` |
| `FfcKeyAgreement.DiffieHellman`, `FfcSchemes.DhEphemeral`, `DhHybrid1`, ... | `FfcSchemes` with the same method names as `EcSchemes` |
| `FfcDomainAssurance.Fips186ProbablePrimeValidation(seed, counter, FfcDomainParameterHash)` | `FfcDomainAssurance.Fips186Evidence(seed, counter, NistHashAlgorithm)` |
| `SharedSecret` | `byte[]` (clear it when done) |
| `Sp80056AKeyConfirmation`, `KeyConfirmationAlgorithm`, `KeyConfirmationParty` | `KeyConfirmation` / `IKeyConfirmation`, `KeyConfirmationMac`, `Party` |
| `SecureKeyDerivation` (`Kdf108.Simple`) | `Sp800108.Derive` and the SP 800-56A/56C classes directly |
| per-call `ILogger` parameters, `Sp800108Debug`, `Sp80056ADebug` | the DI services, which log through `ILogger<T>` |
| About 30 exception types | `Kdf108Exception`: `KdfParameterException`, `InvalidKeyException` (with `KeyFailure`), `KeyAgreementException` |

Behavior changes to be aware of:

- SP 800-108 counter widths are limited to 8, 16, 24, and 32 bits. Other widths were encoded
  incorrectly before.
- KMAC key confirmation now uses the customization string "KC", and the tag length is KMAC's
  output length. Tags from 2.x KMAC key confirmation will not verify.
- EC public keys with x = 0 or y = 0 are now accepted, as the standard requires.
- FIPS 186-type parameters vouched for by a trusted authority skip the primality tests; the
  authority provides that assurance. Use `Fips186Evidence` to have the library check primality.
