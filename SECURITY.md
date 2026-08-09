# MoniCheck Security Policy

MoniCheck reads monitoring configuration and operational evidence inside the
operator's environment. Security reports are treated as product-boundary
reports, not as general support requests.

## Supported Versions

The latest published release receives security fixes. Before the first public
release, the current `main` branch is the only supported source state.

## Report A Vulnerability

Use the repository **Security** tab and select **Report a vulnerability**. This
creates a private GitHub Security Advisory visible only to the reporter and
maintainers. Do not place vulnerability details, credentials, endpoints,
private reports, resource names, or exploit material in a public issue.

If private vulnerability reporting is not enabled, open a content-free public
issue asking maintainers to enable the private channel. Include no technical
details until a private advisory is available.

Include, when safe:

- affected MoniCheck version, commit, OS, and architecture;
- the affected trust boundary and minimum reproduction steps;
- expected and observed behavior;
- whether credentials, private source data, tenant isolation, report exports,
  execution authority, or signature verification may be affected;
- a proposed mitigation, if known.

Do not test against systems you do not own or have explicit permission to use.

## Data Boundaries

- `activation-receipt.v1` is designed for manual sharing after review. It
  excludes endpoints, credentials, resource names, detailed finding evidence,
  and user or machine identity.
- Governance reports, Local state, raw logs, connector diagnostics, and source
  configuration are private operational artifacts. Keep them inside the
  operator's controlled environment unless its own security process approves
  disclosure.
- Connector secrets belong in environment variables or the documented
  write-only configuration path. Never attach them to an issue or advisory.

MoniCheck has no automatic telemetry or report-upload path in Local mode.

## Disclosure

Maintainers will acknowledge a complete private report on a best-effort basis,
coordinate remediation and release timing with the reporter, and credit the
reporter when requested. This project currently provides no contractual
response-time SLA.
