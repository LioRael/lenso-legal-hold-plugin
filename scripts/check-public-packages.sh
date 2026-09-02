#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
package_flags=(--locked)
if [[ "${LENSO_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
  package_flags+=(--allow-dirty)
fi

"$cargo_bin" package "${package_flags[@]}" -p lenso-capability-legal-hold
"$cargo_bin" package "${package_flags[@]}" -p lenso-legal-hold-postgres-plugin
