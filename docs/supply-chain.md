# Release Supply Chain

Official GitHub releases contain four static Go archives, `SHA256SUMS`,
`release-manifest.v1.json`, and a CycloneDX 1.5 SBOM.

The release build:

- exports the reviewed Local-only source boundary;
- binds version, source commit, and UTC build time into every binary;
- uses the source commit timestamp through `SOURCE_DATE_EPOCH`;
- builds with `CGO_ENABLED=0`, `-trimpath`, and `-buildvcs=false`;
- creates archives with deterministic ordering, timestamps, modes, and gzip
  metadata;
- records every archive and SBOM digest in `SHA256SUMS`.

Verify checksums before installation and compare `monicheck version --format json`
with the release manifest. Rebuilding requires the Go version declared by `go.mod`,
the tagged source commit, and its commit timestamp.

Current releases are checksum-protected but are not code-signed or accompanied by
a Sigstore provenance attestation. The manifest and SBOM improve inspection; they
do not claim a signed build identity.
