# Kdf108

[![Build](https://github.com/OpenPhysical/Kdf108/actions/workflows/build.yml/badge.svg)](https://github.com/OpenPhysical/Kdf108/actions/workflows/build.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

Kdf108 is a .NET implementation of NIST SP 800-108 key derivation functions, SP 800-56A
finite-field and elliptic-curve key agreement, and SP 800-56C Rev. 2 key-derivation methods.
It supports counter, feedback, and double-pipeline modes with approved HMAC and AES-CMAC
pseudorandom functions, plus the dedicated SP 800-108 Rev. 1 KMAC128 and KMAC256 KDF.
TDEA-based KDFs are deliberately unavailable because NIST disallows them for new use.

## Requirements

- .NET 10 SDK for repository development
- .NET 9 or .NET 10 for library consumers

## Build and test

```bash
dotnet restore
dotnet build --configuration Release
dotnet test --configuration Release
```

The ordinary test command is the fast developer gate. The release workflow also positively
selects the long-running SP 800-108 and SP 800-56A CAVP lanes and verifies their TRX execution
counts against `tests/conformance-manifest.json`; merely loading vector files is not accepted as
conformance evidence. Historical SP 800-56A fixtures with known mutation/MAC harness gaps run
in a separate diagnostic lane and cannot satisfy the release conformance gate.

## Packages

Kdf108 3.0 targets `net9.0` and `net10.0`. NuGet publishing follows signed
version tags after the complete build and test workflow passes.

## Conformance

The test suite includes NIST CAVP SP 800-108 and SP 800-56A response vectors, independent
SP 800-56C checks, and negative tests for rejected states. See the
[standards coverage matrix](docs/standards-coverage.md) for the evidence boundary.

Version 3 replaces the mutable SP 800-56C configuration surface with closed, immutable request
types. Shared secrets and SP 800-56C requests own sensitive copies and must be disposed after
use. See the [3.0 migration guide](docs/migration-v3.md).

## Project policies

- [Contributing guide](CONTRIBUTING.md)
- [Contributor copyright assignment](CONTRIBUTOR_ASSIGNMENT.md)
- [Bounded Contribution Policy](CODE_OF_CONDUCT.md)
- [Commercial licensing](COMMERCIAL-LICENSING.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## Licensing

The repository and public NuGet package are licensed under the
[GNU Affero General Public License v3.0 only](LICENSE), identified by SPDX as `AGPL-3.0-only`.
Organizations that need different terms may request a separately negotiated
[commercial license](COMMERCIAL-LICENSING.md).
