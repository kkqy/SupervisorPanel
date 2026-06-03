#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/scripts/lib-systemd.sh"

run_case() {
  local name="$1"
  local input="$2"
  local expected="$3"
  local expected_changed="$4"
  local tmp_dir service_file expected_file
  tmp_dir="$(mktemp -d)"
  service_file="${tmp_dir}/supervisor-panel.service"
  expected_file="${tmp_dir}/expected.service"
  printf '%s\n' "${input}" > "${service_file}"
  printf '%s\n' "${expected}" > "${expected_file}"

  migrate_supervisor_panel_service_unit "${service_file}"
  if [[ "${SERVICE_UNIT_CHANGED:-}" != "${expected_changed}" ]]; then
    echo "case '${name}' expected changed=${expected_changed}, got ${SERVICE_UNIT_CHANGED:-unset}" >&2
    rm -rf "${tmp_dir}"
    exit 1
  fi
  if ! cmp -s "${expected_file}" "${service_file}"; then
    echo "case '${name}' failed" >&2
    echo "expected:" >&2
    cat "${expected_file}" >&2
    echo "actual:" >&2
    cat "${service_file}" >&2
    rm -rf "${tmp_dir}"
    exit 1
  fi

  migrate_supervisor_panel_service_unit "${service_file}"
  if [[ "${SERVICE_UNIT_CHANGED:-}" != "0" ]]; then
    echo "case '${name}' expected second run to be unchanged, got ${SERVICE_UNIT_CHANGED:-unset}" >&2
    rm -rf "${tmp_dir}"
    exit 1
  fi
  rm -rf "${tmp_dir}"
}

run_case \
  "migrate hard dependency" \
  $'[Unit]\nDescription=SupervisorPanel Web Manager\nAfter=network.target supervisor.service\nRequires=supervisor.service\n\n[Service]\nType=simple' \
  $'[Unit]\nDescription=SupervisorPanel Web Manager\nAfter=network.target supervisor.service\nWants=supervisor.service\n\n[Service]\nType=simple' \
  "1"

run_case \
  "already weak dependency" \
  $'[Unit]\nDescription=SupervisorPanel Web Manager\nAfter=network.target supervisor.service\nWants=supervisor.service\n\n[Service]\nType=simple' \
  $'[Unit]\nDescription=SupervisorPanel Web Manager\nAfter=network.target supervisor.service\nWants=supervisor.service\n\n[Service]\nType=simple' \
  "0"

echo "systemd service tests passed"
