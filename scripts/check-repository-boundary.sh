#!/usr/bin/env bash
set -euo pipefail

expected_crates=$'lenso-capability-support-sla\nlenso-support-sla-postgres-plugin'
actual_crates="$(find crates -mindepth 2 -maxdepth 2 -name Cargo.toml -print0 | xargs -0 sed -n 's/^name = "\([^"]*\)"/\1/p' | LC_ALL=C sort)"
[[ "$actual_crates" == "$expected_crates" ]] || { printf 'unexpected workspace crate boundary\n%s\n' "$actual_crates" >&2; exit 1; }

if rg -n 'path\s*=\s*"(\.\./\.\./|/)' --glob Cargo.toml .; then
  echo 'cross-repository or absolute path dependency found' >&2
  exit 1
fi
if rg -n '/Users/|file://' README.md docs crates .github Cargo.toml; then
  echo 'machine-local path leaked into a public artifact' >&2
  exit 1
fi
if rg -n 'lenso-capability-support-case|CREATE TABLE (support_cases|support_case_messages)' crates --glob '!**/generated.rs'; then
  echo 'Support SLA crossed the Support Case ownership boundary' >&2
  exit 1
fi
if rg -n 'lenso-capability-notification|create_organization_invitation|create_access_request_notification' crates --glob '!**/generated.rs'; then
  echo 'Support SLA misused a workflow-specific Notification contract' >&2
  exit 1
fi
if rg -n 'HashMap|Mutex<.*Vec|memory fallback|in.memory' crates --glob '*.rs'; then
  echo 'ambient in-memory durable state found' >&2
  exit 1
fi
if rg -n 'lenso-platform-|lenso-module-|HostBuilder|HostLinkedModule|ModuleManifest' Cargo.toml crates README.md docs --glob '!**/generated.rs'; then
  echo 'legacy Lenso API found' >&2
  exit 1
fi
if rg -n 'message_body|body_snapshot|requester_email' crates/lenso-capability-support-sla; then
  echo 'sensitive Support Case payload entered the SLA contract' >&2
  exit 1
fi
for capability in lenso.support-sla@1 lenso.secrets@1 lenso.organization-membership@1 lenso.access-control@1 lenso.jobs@1; do
  rg -q "$capability" README.md docs crates || { echo "missing documented Capability: $capability" >&2; exit 1; }
done
rg -q 'ManyPort<jobs::JobsClient>' crates/lenso-support-sla-postgres-plugin/src/lib.rs || { echo 'Jobs must remain an explicit zero-or-one typed boundary' >&2; exit 1; }
