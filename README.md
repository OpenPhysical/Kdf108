# Kdf108

[![Build](https://github.com/OpenPhysical/Kdf108/actions/workflows/build.yml/badge.svg)](https://github.com/OpenPhysical/Kdf108/actions/workflows/build.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0--only-blue.svg)](LICENSE)

Kdf108 is a .NET implementation of NIST SP 800-108 key derivation functions, SP 800-56A
elliptic-curve key agreement, and SP 800-56C key-derivation pipelines. It supports counter,
feedback, and double-pipeline modes with HMAC and CMAC pseudorandom functions.

## Requirements

- .NET 10 SDK for repository development
- .NET 9 or .NET 10 for library consumers

## Build and test

```bash
dotnet restore
dotnet build --configuration Release
dotnet test --configuration Release
```

## Packages

Kdf108 2.1 targets `net9.0` and `net10.0`. NuGet publishing follows signed
version tags after the complete build and test workflow passes.

## Conformance

The test suite includes NIST CAVP SP 800-108 and SP 800-56A response vectors, plus SP 800-56C
vectors. Passing these vectors demonstrates compatibility with those published test cases; it is
not a NIST validation or endorsement.

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
