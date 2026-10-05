# Kdf108

[![Build](https://github.com/OpenPhysical/Kdf108/actions/workflows/build.yml/badge.svg)](https://github.com/OpenPhysical/Kdf108/actions/workflows/build.yml)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://openphysical.github.io/Kdf108/)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

Kdf108 is a small .NET library for the NIST key-establishment toolkit:

- **SP 800-108 Rev. 1**: derive keys from a key you already have (counter, feedback, and
  double-pipeline modes with HMAC or AES-CMAC, plus the KMAC-based KDF).
- **SP 800-56A Rev. 3**: agree on a shared secret with someone else (ECC and finite-field
  Diffie-Hellman and MQV, every scheme, with full key validation and key confirmation).
- **SP 800-56C Rev. 2**: turn that shared secret into keys (one-step and two-step derivation).

It runs on .NET 9 and .NET 10, uses Bouncy Castle for the underlying primitives, and is checked
against more than 177,000 NIST CAVP test vectors on every change.

**Documentation:** <https://openphysical.github.io/Kdf108/>

## Install

```bash
dotnet add package Kdf108
```

## Deriving a key

If you have a key-derivation key (from a key store, a KMS, or an earlier key agreement), give
each use its own label and context and you get independent keys:

<!-- snippet: quickstart-sp800108 -->
```csharp
byte[] key = Sp800108.Derive(
    keyDerivationKey,
    Prf.Hmac(NistHashAlgorithm.Sha256),
    label: "file-encryption"u8,
    context: "tenant:42"u8,
    BitLength.Create(256));
```

## Agreeing on a key

Two parties each generate a key pair and swap public keys. Each side validates the other's key,
computes the shared secret Z, and derives the actual key from it with SP 800-56C:

<!-- snippet: quickstart-agreement -->
```csharp
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
```

Z itself is never a key. Always run it through `Sp80056C`, then clear it.

## Dependency injection and logging

The static classes above are pure functions. If you use dependency injection, register the
services instead; each one mirrors a static class method for method and logs through your
application's logging (algorithms and lengths only, never key material):

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

Every service is a public sealed class you can also construct yourself, with or without a logger.

## Learn more

- [API guide](docs/api.md): every mode, scheme, and option, with examples.
- [Domain separation](docs/domain-separation.md): how to choose labels, contexts, and FixedInfo.
- [Standards coverage](docs/standards-coverage.md): what is implemented and how it is tested.
- [Migrating to 3.0](docs/migration-v3.md): the old API mapped to the new one.
- [Examples](examples/README.md): a small command-line app you can run and read.

## Building and testing

```bash
dotnet build
dotnet test     # the fast lane: unit tests, pinned answers, and smoke runs (a few seconds)
make cavp       # every NIST CAVP vector, verified exactly as CI does (a couple of minutes)
```

## Contributing and licensing

Kdf108 is licensed under the [GNU Affero General Public License v3.0 only](LICENSE)
(`AGPL-3.0-only`). If you need different terms, ask about a
[commercial license](COMMERCIAL-LICENSING.md).

Before contributing, please read the [contributing guide](CONTRIBUTING.md), the
[contributor copyright assignment](CONTRIBUTOR_ASSIGNMENT.md), and the
[Bounded Contribution Policy](CODE_OF_CONDUCT.md). Third-party notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
