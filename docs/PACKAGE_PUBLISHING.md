# Private development package publication

The manual `Publish immutable DEV package` workflow publishes the reviewed `master` commit to the private OpenPhysical GitHub Packages feed. The workflow declares the exact version `3.0.1-dev.20261116.2`. Change that version in reviewed source before another publication. The earlier local `.1` bootstrap archive remains separate evidence.

The workflow restores the committed dependency locks, builds and tests both supported frameworks, and binds the package metadata and archive contents to the checked-out source commit. Before upload, it requires the package to be absent or private and linked to `OpenPhysical/Kdf108`, rejects both active and deleted version collisions, and retains the candidate archive and manifest. After upload, an isolated authenticated NuGet restore must reproduce the exact archive bytes and entry hashes. The receipt records private visibility and owning repository linkage. Credentials are supplied through environment variables.

The symbol archive is retained with the candidate artifact; only the `.nupkg` is pushed to the private feed. The existing tagged NuGet.org publisher remains the public release path. This development workflow creates no public release or tag and does not change existing package visibility.

Before consumers can restore the private version, grant Actions package read access to the specific consumer repositories. Their workflows need `packages: read`, explicit credentials for the `openphysical` source, and an exact package-source mapping for `Kdf108`. These grants must be verified by fresh consumer builds; publisher success alone does not establish cross-repository access. Update consumer version and lock hashes only after accepting the publication receipt.
