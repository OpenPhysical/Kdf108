# Contributing to Kdf108

Kdf108 welcomes focused technical contributions that improve its SP 800-108 implementation,
tests, documentation, packaging, or supported integrations.

## Before contributing

Participation is governed by the [Bounded Contribution Policy](CODE_OF_CONDUCT.md). Code and
documentation contributions also require acceptance of the
[Contributor Copyright Assignment](CONTRIBUTOR_ASSIGNMENT.md) through the repository's CLA check.

The assignment preserves OpenPhysical's ability to offer commercial licenses while promising that
accepted contributions remain available under the repository's AGPL license. A contributor keeps a
broad license to reuse their own contribution.

If an employer or another organization owns your contribution, an authorized representative must
complete the entity assignment. Do not submit third-party code, generated material, test vectors,
or documentation unless its origin and license are disclosed and compatible.

## Development

```bash
git clone https://github.com/OpenPhysical/Kdf108.git
cd Kdf108
dotnet restore
dotnet build --configuration Release
dotnet test --configuration Release
```

Use the .NET 10 SDK. Treat compiler warnings as failures, keep public APIs documented, preserve
deterministic test vectors, and add tests for behavioral changes.

## Pull requests

Create a branch from `master`, make signed commits, and open a pull request. Before requesting
review:

1. Run the Release build and full test suite.
2. Update user-facing documentation when behavior changes.
3. Describe any third-party material in the pull request.
4. Complete the CLA Assistant check for every human commit author.
5. Confirm the pull request checklist.

All changes, including maintainer changes, require a pull request, passing CI, valid signed commits,
and contributor-rights coverage. Acceptance remains at maintainer discretion.

Questions about contribution rights or commercial licensing belong at
[opensource@mistial.dev](mailto:opensource@mistial.dev). Security issues should not be filed in a
public issue; email the same address with `Kdf108 security` in the subject.
