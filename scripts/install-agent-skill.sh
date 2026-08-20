#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_dir="$root/.agents/skills/monicheck-observability-audit"
target_root="${HOME}/.agents/skills"
force=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --codex)
      target_root="${CODEX_HOME:-${HOME}/.codex}/skills"
      shift
      ;;
    --target)
      [ "$#" -ge 2 ] || { echo "--target requires a directory" >&2; exit 2; }
      target_root="$2"
      shift 2
      ;;
    --force)
      force=true
      shift
      ;;
    -h|--help)
      echo "usage: install-agent-skill.sh [--codex | --target DIR] [--force]"
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done

destination="$target_root/monicheck-observability-audit"
if [ -e "$destination" ]; then
  if [ "$force" != true ]; then
    echo "skill already exists: $destination (use --force to replace it)" >&2
    exit 2
  fi
  rm -rf "$destination"
fi

mkdir -p "$target_root"
cp -R "$source_dir" "$destination"
echo "Installed MoniCheck skill at $destination"
