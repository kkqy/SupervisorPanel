#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

assert_standalone_script_reaches_root_check() {
  local script_name="$1"
  local tmp_dir output status
  tmp_dir="$(mktemp -d)"
  cp "${ROOT_DIR}/scripts/${script_name}" "${tmp_dir}/${script_name}"

  status=0
  output="$(bash "${tmp_dir}/${script_name}" 2>&1 </dev/null)" || status="$?"
  rm -rf "${tmp_dir}"

  if [[ "${status}" == "0" ]]; then
    echo "expected ${script_name} to stop before installation when not root" >&2
    exit 1
  fi
  if [[ "${output}" != *"请使用 root"* ]]; then
    echo "expected ${script_name} to be standalone and reach root check" >&2
    echo "actual output:" >&2
    printf '%s\n' "${output}" >&2
    exit 1
  fi
}

assert_standalone_script_reaches_root_check "install.sh"
assert_standalone_script_reaches_root_check "upgrade.sh"
assert_standalone_script_reaches_root_check "uninstall.sh"

echo "standalone script tests passed"
