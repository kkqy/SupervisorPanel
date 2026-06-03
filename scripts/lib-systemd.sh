#!/usr/bin/env bash

migrate_supervisor_panel_service_unit() {
  local service_file="${1:-${SERVICE_FILE:-/etc/systemd/system/supervisor-panel.service}}"
  local tmp_file

  SERVICE_UNIT_CHANGED=0

  if [[ ! -f "${service_file}" ]]; then
    return 0
  fi
  if ! grep -Eq '^[[:space:]]*Requires[[:space:]]*=[[:space:]]*supervisor\.service[[:space:]]*$' "${service_file}"; then
    return 0
  fi

  tmp_file="$(mktemp)"
  sed -E 's/^[[:space:]]*Requires[[:space:]]*=[[:space:]]*supervisor\.service[[:space:]]*$/Wants=supervisor.service/' "${service_file}" > "${tmp_file}"
  if ! cmp -s "${tmp_file}" "${service_file}"; then
    cat "${tmp_file}" > "${service_file}"
    SERVICE_UNIT_CHANGED=1
    echo "已将 supervisor-panel.service 的 Supervisor 依赖改为 Wants"
  fi
  rm -f "${tmp_file}"
}
