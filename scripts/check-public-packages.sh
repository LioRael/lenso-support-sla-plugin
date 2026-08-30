#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${LENSO_CARGO_BIN:-}" ]]; then
  cargo_bin="$LENSO_CARGO_BIN"
else
  cargo_bin=cargo
fi
flags=(--locked)
if [[ "${LENSO_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then flags+=(--allow-dirty); fi

for manifest in crates/*/Cargo.toml; do
  rg -qx 'publish = true' "$manifest" || { echo "$manifest is not explicitly publishable" >&2; exit 1; }
done

"$cargo_bin" package "${flags[@]}" -p lenso-capability-support-sla
"$cargo_bin" package "${flags[@]}" --no-verify -p lenso-support-sla-postgres-plugin \
  --config 'patch.crates-io.lenso-capability-support-sla.path="crates/lenso-capability-support-sla"'

target="$($cargo_bin metadata --no-deps --format-version=1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
for package in lenso-capability-support-sla lenso-support-sla-postgres-plugin; do
  version="$($cargo_bin metadata --no-deps --format-version=1 | python3 -c 'import json,sys; name=sys.argv[1]; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == name))' "$package")"
  test -s "$target/package/$package-$version.crate"
done
