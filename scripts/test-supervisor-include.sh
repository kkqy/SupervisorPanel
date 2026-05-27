#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${ROOT_DIR}/scripts/lib-supervisor.sh"

TARGET_LINE="files = /etc/supervisor/conf.d/*.conf"

assert_contains_once() {
  local file="$1"
  local count
  count="$(grep -Fxc "${TARGET_LINE}" "${file}" || true)"
  if [[ "${count}" != "1" ]]; then
    echo "expected one active include line in ${file}, got ${count}" >&2
    cat "${file}" >&2
    exit 1
  fi
}

assert_has_active_include_section() {
  local file="$1"
  if ! grep -Fxq "[include]" "${file}"; then
    echo "expected active [include] section in ${file}" >&2
    cat "${file}" >&2
    exit 1
  fi
}

run_case() {
  local name="$1"
  local input="$2"
  local expected="$3"
  local expected_changed="$4"
  local tmp_dir conf_file expected_file
  tmp_dir="$(mktemp -d)"
  conf_file="${tmp_dir}/supervisord.conf"
  expected_file="${tmp_dir}/expected.conf"
  printf '%s\n' "${input}" > "${conf_file}"
  printf '%s\n' "${expected}" > "${expected_file}"

  ensure_supervisor_include "${conf_file}"
  if [[ "${SUPERVISOR_INCLUDE_CHANGED:-}" != "${expected_changed}" ]]; then
    echo "case '${name}' expected changed=${expected_changed}, got ${SUPERVISOR_INCLUDE_CHANGED:-unset}" >&2
    rm -rf "${tmp_dir}"
    exit 1
  fi
  if ! cmp -s "${expected_file}" "${conf_file}"; then
    echo "case '${name}' failed" >&2
    echo "expected:" >&2
    cat "${expected_file}" >&2
    echo "actual:" >&2
    cat "${conf_file}" >&2
    rm -rf "${tmp_dir}"
    exit 1
  fi

  ensure_supervisor_include "${conf_file}"
  if [[ "${SUPERVISOR_INCLUDE_CHANGED:-}" != "0" ]]; then
    echo "case '${name}' expected second run to be unchanged, got ${SUPERVISOR_INCLUDE_CHANGED:-unset}" >&2
    rm -rf "${tmp_dir}"
    exit 1
  fi
  assert_has_active_include_section "${conf_file}"
  assert_contains_once "${conf_file}"
  rm -rf "${tmp_dir}"
}

run_case \
  "already active" \
  $'[unix_http_server]\nfile=/var/run/supervisor.sock\n\n[include]\nfiles = /etc/supervisor/conf.d/*.conf' \
  $'[unix_http_server]\nfile=/var/run/supervisor.sock\n\n[include]\nfiles = /etc/supervisor/conf.d/*.conf' \
  "0"

run_case \
  "commented include section" \
  $'[unix_http_server]\nfile=/var/run/supervisor.sock\n\n;[include]\n;files = /etc/supervisor/conf.d/*.conf' \
  $'[unix_http_server]\nfile=/var/run/supervisor.sock\n\n[include]\nfiles = /etc/supervisor/conf.d/*.conf' \
  "1"

run_case \
  "missing include section" \
  $'[unix_http_server]\nfile=/var/run/supervisor.sock' \
  $'[unix_http_server]\nfile=/var/run/supervisor.sock\n\n[include]\nfiles = /etc/supervisor/conf.d/*.conf' \
  "1"

run_case \
  "include section without target files" \
  $'[unix_http_server]\nfile=/var/run/supervisor.sock\n\n[include]\nfiles = relative/directory/*.ini\n\n[supervisord]\nlogfile=/var/log/supervisor/supervisord.log' \
  $'[unix_http_server]\nfile=/var/run/supervisor.sock\n\n[include]\nfiles = relative/directory/*.ini\nfiles = /etc/supervisor/conf.d/*.conf\n\n[supervisord]\nlogfile=/var/log/supervisor/supervisord.log' \
  "1"

run_case \
  "commented files in active include section" \
  $'[include]\n# files = /etc/supervisor/conf.d/*.conf' \
  $'[include]\nfiles = /etc/supervisor/conf.d/*.conf' \
  "1"

echo "supervisor include tests passed"
