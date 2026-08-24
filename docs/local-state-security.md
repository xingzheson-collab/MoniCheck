# Local State Security Boundary

MoniCheck Local state is owner evidence, not an anonymous telemetry cache. It can
contain resource names, labels, normalized queries, finding evidence, coverage
expectations, exceptions, and local history. Treat it with the same access policy
as monitoring configuration and incident artifacts.

- The file store is created with owner-only `0600` permissions and replaced
  atomically.
- Provider credentials are read from process environment variables and are not
  written into Local state.
- Connector sanitization removes raw datasource URLs where the evidence contract
  requires only a fingerprint. This does not make the whole state file public.
- `--serve-only` reads the existing file without contacting providers.
- MCP aggregate results are bounded, but the underlying state remains owner-only.
- Backups, CI artifacts, shell history, and shared volumes must preserve the same
  access boundary. Do not commit a state file to Git or attach it to a public issue.

Delete the state file when its local retention purpose ends. Managed upload is
never automatic; review any explicit export before moving it outside the host.
