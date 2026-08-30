#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
package_flags=(--locked)
if [[ "${LENSO_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
  package_flags+=(--allow-dirty)
fi

"$cargo_bin" package "${package_flags[@]}" -p lenso-capability-legal-hold

# The Plugin's own Capability and Retention Guard are unpublished during the
# first release, so Cargo cannot yet resolve the normalized registry manifest.
# Inspect the exact package source set now; the workspace gates exercise the
# complete pinned source graph and the release dry-run becomes strict after the
# Capability names exist in the registry.
plugin_sources="$("$cargo_bin" package "${package_flags[@]}" --list \
  -p lenso-legal-hold-postgres-plugin)"
for required in \
  Cargo.toml \
  configuration.schema.json \
  migrations/001_create_legal_holds.sql \
  src/lib.rs \
  src/storage.rs; do
  if ! grep -Fxq "$required" <<<"$plugin_sources"; then
    echo "Plugin package source set is missing $required" >&2
    exit 1
  fi
done
