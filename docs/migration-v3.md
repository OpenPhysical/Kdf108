# Migrating to Kdf108 3.0

Version 3 targets .NET 9 and .NET 10. It introduces immutable, closed SP 800-56C request types
so callers cannot combine extraction and expansion algorithms that the recommendation forbids.
The 2.x `Sp80056COptions`, builder, and pipeline classes are no longer public API.

## One-step derivation

Construct a `OneStepKdfRequest` with a `BitLength`, `SecurityStrength`, and one of the factories
on `OneStepAuxiliaryFunction`, then call `Sp80056COneStep.Derive`.

```csharp
var request = new OneStepKdfRequest(
    sharedSecret,
    fixedInfo,
    BitLength.Create(256),
    SecurityStrength.Bits128,
    OneStepAuxiliaryFunction.HmacFunction(NistHashAlgorithm.Sha256));

byte[] key = Sp80056COneStep.Derive(request);
```

`fixedInfo` is a byte string. Encode protocol fields explicitly so both parties use one canonical,
unambiguous representation.

## Two-step derivation

Choose extraction first. HMAC extraction fixes the expansion PRF to the same HMAC. AES-CMAC
extraction fixes expansion to AES-128-CMAC. The API does not expose the forbidden pairings.

```csharp
var request = new TwoStepKdfRequest(
    sharedSecret,
    TwoStepExtraction.HmacFunction(NistHashAlgorithm.Sha256),
    SecurityStrength.Bits128,
    new[]
    {
        KeyExpansion.CounterMode(fixedInfo, BitLength.Create(256))
    });

byte[] key = Sp80056CTwoStep.Derive(request)[0];
```

Output length is measured in bits. A request for 9 bits returns two bytes with the unused low
seven bits of the final byte cleared.

## Text labels

Pass protocol labels as bytes. If a protocol defines labels as text, encode them with strict UTF-8.
Malformed UTF-16 input is rejected rather than replaced, preventing different labels from
collapsing to the same derivation input.
