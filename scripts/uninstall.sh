#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行卸载脚本" >&2
  exit 1
fi

INSTALL_DIR="${INSTALL_DIR:-/opt/supervisor-panel}"
DATA_DIR="${DATA_DIR:-/var/lib/supervisor-panel}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/supervisor-panel}"
ENV_DIR="${ENV_DIR:-/etc/supervisor-panel}"
SERVICE_FILE="${SERVICE_FILE:-/etc/systemd/system/supervisor-panel.service}"
SUPERVISOR_CONF_DIR="${SUPERVISOR_CONF_DIR:-/etc/supervisor/conf.d}"
SUPERVISOR_LOG_DIR="${SUPERVISOR_LOG_DIR:-/var/log/supervisor-panel}"
REMOVE_DATA="${REMOVE_DATA:-0}"
ASSUME_YES="${ASSUME_YES:-0}"

is_truthy() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|y|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

confirm_uninstall() {
  if is_truthy "${ASSUME_YES}"; then
    return 0
  fi

  echo "将卸载 SupervisorPanel 服务和程序文件。"
  echo "默认保留项目、数据库、配置和日志；如需同时删除数据，请设置 REMOVE_DATA=1。"
  read -r -p "确认继续卸载？[y/N]: " answer
  if ! is_truthy "${answer}"; then
    echo "已取消卸载。"
    exit 0
  fi
}

remove_panel_supervisor_configs() {
  local removed=0
  local conf_file

  if [[ ! -d "${SUPERVISOR_CONF_DIR}" ]]; then
    return 0
  fi

  shopt -s nullglob
  for conf_file in "${SUPERVISOR_CONF_DIR}"/sp_*.conf; do
    if grep -qE '^[[:space:]]*\[program:sp_' "${conf_file}" && grep -Fq "${SUPERVISOR_LOG_DIR}/" "${conf_file}"; then
      rm -f "${conf_file}"
      removed=1
      echo "已删除 Supervisor 项目配置: ${conf_file}"
    fi
  done
  shopt -u nullglob

  if [[ "${removed}" == "1" ]] && command -v supervisorctl >/dev/null 2>&1; then
    supervisorctl reread || true
    supervisorctl update || true
  fi
}

confirm_uninstall

echo "[1/5] 停止并禁用 systemd 服务..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop supervisor-panel 2>/dev/null || true
  systemctl disable supervisor-panel 2>/dev/null || true
fi

echo "[2/5] 删除 systemd 服务文件..."
rm -f "${SERVICE_FILE}"
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  systemctl reset-failed supervisor-panel 2>/dev/null || true
fi

echo "[3/5] 删除面板生成的 Supervisor 项目配置..."
remove_panel_supervisor_configs

echo "[4/5] 删除程序和脚本文件..."
rm -f "${BIN_PATH}"
rm -f "${INSTALL_DIR}/upgrade.sh" "${INSTALL_DIR}/uninstall.sh"
rmdir "${INSTALL_DIR}" 2>/dev/null || true

echo "[5/5] 处理数据目录..."
if is_truthy "${REMOVE_DATA}"; then
  rm -rf "${INSTALL_DIR}" "${DATA_DIR}" "${ENV_DIR}" "${SUPERVISOR_LOG_DIR}"
  echo "已删除项目、数据库、配置和日志目录。"
else
  echo "已保留数据目录: ${DATA_DIR}"
  echo "已保留配置目录: ${ENV_DIR}"
  echo "已保留项目目录: ${INSTALL_DIR}/projects"
  echo "已保留日志目录: ${SUPERVISOR_LOG_DIR}"
fi

echo "卸载完成。"
