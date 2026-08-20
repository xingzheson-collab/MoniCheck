#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
skill="$root/.agents/skills/monicheck-observability-audit"

test -f "$skill/SKILL.md"
test -x "$skill/scripts/run-audit.sh"
grep -Fq "name: monicheck-observability-audit" "$skill/SKILL.md"
grep -Fq 'monicheck.audit.run' "$skill/SKILL.md"
grep -Fq 'UNKNOWN' "$skill/references/evidence-model.md"

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
HOME="$temporary" "$root/scripts/install-agent-skill.sh" >/dev/null
test -f "$temporary/.agents/skills/monicheck-observability-audit/SKILL.md"

echo "Agent skill contract passed."
