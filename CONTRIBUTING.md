# Contributing to MoniCheck

MoniCheck is currently optimizing for Local-first activation and trustworthy
Coverage/Risk evidence. Contributions should improve the first real scan,
finding quality, privacy boundaries, report explainability, or repeat-scan
comparison. New connector and analyzer counts are not goals by themselves.

## Development

```bash
make monicheck-build
make monicheck-test
make website-lint
make website-build
```

Use `make monicheck-demo-source` only for UI and installation checks. Analyzer
claims must be tested with complete evidence, incomplete evidence, and a
negative case that proves Unknown data does not become a Missing claim.

## Product Boundaries

- Local Report must work without an account or outbound MoniCheck connection.
- Built-in user-visible Evidence and Recommendation text must be English;
  custom Rule Engine policies may retain the author's chosen language.
- Connector credentials and arbitrary metadata must not enter report exports.
- Hybrid Managed remains optional after local value and accepts bounded
  summaries rather than raw customer configuration by default.
- Billing automation, multi-region, SCIM, and additional commercial adapter
  contracts remain frozen until the RFC-0242 demand gates are met.

## Pull Requests

Describe the user problem, the evidence required for the conclusion, privacy
impact, tests run, and UI/RFC changes. Include desktop and mobile screenshots
for product-surface changes. By submitting a contribution, you agree that it
is licensed under Apache License 2.0.
