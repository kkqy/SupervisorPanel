#!/usr/bin/env bash

SUPERVISORD_CONF="${SUPERVISORD_CONF:-/etc/supervisor/supervisord.conf}"
SUPERVISOR_INCLUDE_LINE="files = /etc/supervisor/conf.d/*.conf"

ensure_supervisor_include() {
  local conf_path="${1:-${SUPERVISORD_CONF}}"
  local tmp_file

  SUPERVISOR_INCLUDE_CHANGED=0

  if [[ ! -f "${conf_path}" ]]; then
    echo "未找到 Supervisor 主配置文件: ${conf_path}" >&2
    return 1
  fi

  tmp_file="$(mktemp)"
  awk -v target="${SUPERVISOR_INCLUDE_LINE}" '
    function is_section(line) {
      return line ~ /^[[:space:]]*\[[^]]+\][[:space:]]*$/ || line ~ /^[[:space:]]*[#;][[:space:]]*\[[^]]+\][[:space:]]*$/
    }
    function active_include(line) {
      return line ~ /^[[:space:]]*\[include\][[:space:]]*$/
    }
    function commented_include(line) {
      return line ~ /^[[:space:]]*[#;][[:space:]]*\[include\][[:space:]]*$/
    }
    function active_target(line) {
      return line ~ /^[[:space:]]*files[[:space:]]*=[[:space:]]*\/etc\/supervisor\/conf\.d\/\*\.conf[[:space:]]*$/
    }
    function commented_target(line) {
      return line ~ /^[[:space:]]*[#;][[:space:]]*files[[:space:]]*=[[:space:]]*\/etc\/supervisor\/conf\.d\/\*\.conf[[:space:]]*$/
    }
    function close_include_if_needed(line) {
      if (in_include && is_section(line) && !active_include(line) && !commented_include(line)) {
        if (!target_in_include) {
          print target
          target_in_include = 1
        }
        print_pending_blank()
        in_include = 0
      }
    }
    function print_pending_blank() {
      if (pending_blank != "") {
        printf "%s", pending_blank
        pending_blank = ""
      }
    }
    {
      close_include_if_needed($0)
      if (active_include($0)) {
        found_include = 1
        in_include = 1
        print
        next
      }
      if (commented_include($0)) {
        found_include = 1
        in_include = 1
        print "[include]"
        next
      }
      if (in_include && $0 ~ /^[[:space:]]*$/) {
        pending_blank = pending_blank $0 ORS
        next
      }
      if (in_include && active_target($0)) {
        target_in_include = 1
        print_pending_blank()
        print target
        next
      }
      if (in_include && commented_target($0)) {
        target_in_include = 1
        print_pending_blank()
        print target
        next
      }
      if (in_include) {
        print_pending_blank()
      }
      print
    }
    END {
      if (in_include && !target_in_include) {
        print target
      }
      if (in_include) {
        print_pending_blank()
      }
      if (!found_include) {
        if (NR > 0) {
          print ""
        }
        print "[include]"
        print target
      }
    }
  ' "${conf_path}" > "${tmp_file}"

  if ! cmp -s "${tmp_file}" "${conf_path}"; then
    cat "${tmp_file}" > "${conf_path}"
    SUPERVISOR_INCLUDE_CHANGED=1
    echo "已确保 Supervisor 加载配置目录: /etc/supervisor/conf.d/*.conf"
  fi
  rm -f "${tmp_file}"
}
