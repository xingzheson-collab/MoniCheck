#!/usr/bin/env bash
set -u

usage() {
  echo "usage: run-audit.sh [--binary PATH] [--output-dir DIR] -- [monicheck local source options]" >&2
}

binary="${MONICHECK_BIN:-}"
output_dir="${MONICHECK_AUDIT_OUTPUT_DIR:-./monicheck-audit}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --binary)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      binary="$2"
      shift 2
      ;;
    --output-dir)
      [ "$#" -ge 2 ] || { usage; exit 2; }
      output_dir="$2"
      shift 2
      ;;
    --)
      shift
      break
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

if [ -z "$binary" ]; then
  if command -v monicheck >/dev/null 2>&1; then
    binary="$(command -v monicheck)"
  else
    skill_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    candidate="$skill_dir/../../../bin/monicheck"
    [ -x "$candidate" ] && binary="$candidate"
  fi
fi

if [ -z "$binary" ] || [ ! -x "$binary" ]; then
  echo "MoniCheck binary not found. Set MONICHECK_BIN or pass --binary PATH." >&2
  exit 2
fi

for argument in "$@"; do
  lowercase="$(printf '%s' "$argument" | tr '[:upper:]' '[:lower:]')"
  case "$lowercase" in
    *token*|*password*|*api-key*|*apikey*|*secret*)
      echo "Credential-shaped arguments are not allowed. Use MoniCheck environment variables." >&2
      exit 2
      ;;
    --prometheus-url|--grafana-url|--alertmanager-url|--prometheus-datasource-uid)
      echo "Endpoint arguments are not allowed in the Agent wrapper. Use a local config file or process environment." >&2
      exit 2
      ;;
  esac
done

umask 077
mkdir -p "$output_dir"
gate="$output_dir/gate.json"
gate_temporary="$output_dir/.gate.json.tmp"
bundle="$output_dir/evidence-bundle.json"

"$binary" local "$@" --check --format json --bundle-out "$bundle" >"$gate_temporary"
status=$?

if [ -s "$gate_temporary" ]; then
  mv "$gate_temporary" "$gate"
else
  rm -f "$gate_temporary"
fi

[ -f "$gate" ] && echo "Gate: $gate" >&2
[ -f "$bundle" ] && echo "Agent-safe evidence: $bundle" >&2
exit "$status"
