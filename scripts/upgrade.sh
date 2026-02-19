#!/usr/bin/env bash
set -euo pipefail

USER_VERSION="${VERSION:-}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "请使用 root 运行升级脚本" >&2
  exit 1
fi

if [[ ! -f /etc/os-release ]]; then
  echo "无法识别系统发行版（缺少 /etc/os-release）" >&2
  exit 1
fi

source /etc/os-release
if [[ "${ID:-}" != "ubuntu" && "${ID:-}" != "debian" && "${ID_LIKE:-}" != *"debian"* ]]; then
  echo "当前仅支持 Debian/Ubuntu，检测到: ${PRETTY_NAME:-unknown}" >&2
  exit 1
fi

INSTALL_DIR="/opt/supervisor-panel"
DATA_DIR="/var/lib/supervisor-panel"
BIN_PATH="/usr/local/bin/supervisor-panel"
ENV_FILE="/etc/supervisor-panel/config.env"
SERVICE_FILE="/etc/systemd/system/supervisor-panel.service"

DOWNLOAD_BASE_URL="${DOWNLOAD_BASE_URL:-}"
GITHUB_REPO="${GITHUB_REPO:-kkqy/SupervisorPanel}"
RELEASE_VERSION="${RELEASE_VERSION:-${USER_VERSION:-latest}}"

detect_arch() {
  local machine
  machine="$(uname -m)"
  case "${machine}" in
    x86_64|amd64)
      printf '%s' "amd64"
      ;;
    i386|i686)
      printf '%s' "386"
      ;;
    armv7l|armv6l|arm)
      printf '%s' "arm"
      ;;
    aarch64|arm64)
      printf '%s' "arm64"
      ;;
    *)
      echo "不支持的系统架构: ${machine}" >&2
      exit 1
      ;;
  esac
}

resolve_latest_version() {
  local api_url latest_tag
  api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"

  latest_tag="$(curl -fsSL "${api_url}" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  if [[ -z "${latest_tag}" ]]; then
    echo "无法从 GitHub 获取最新发布版本，请检查仓库: ${GITHUB_REPO}" >&2
    exit 1
  fi

  printf '%s' "${latest_tag}"
}

resolve_package_url() {
  local version="$1"
  local package_name="$2"

  if [[ -n "${DOWNLOAD_BASE_URL}" ]]; then
    printf '%s' "${DOWNLOAD_BASE_URL%/}/${version}/${package_name}"
    return
  fi

  printf '%s' "https://github.com/${GITHUB_REPO}/releases/download/${version}/${package_name}"
}

if [[ "${RELEASE_VERSION}" == "latest" ]]; then
  RELEASE_VERSION="$(resolve_latest_version)"
fi

ARCH="$(detect_arch)"
PACKAGE_NAME="supervisor-panel_${RELEASE_VERSION}_linux_${ARCH}.tar.gz"
PACKAGE_URL="$(resolve_package_url "${RELEASE_VERSION}" "${PACKAGE_NAME}")"

if [[ ! -f "${BIN_PATH}" ]]; then
  echo "未检测到已安装二进制: ${BIN_PATH}" >&2
  echo "请先执行安装脚本，再执行升级脚本" >&2
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "未检测到配置文件: ${ENV_FILE}" >&2
  echo "请先执行安装脚本，再执行升级脚本" >&2
  exit 1
fi

if [[ ! -f "${SERVICE_FILE}" ]]; then
  echo "未检测到 systemd 服务文件: ${SERVICE_FILE}" >&2
  echo "请先执行安装脚本，再执行升级脚本" >&2
  exit 1
fi

echo "[1/6] 安装依赖..."
apt-get update
apt-get install -y ca-certificates curl tar

echo "[2/6] 准备目录..."
mkdir -p "${INSTALL_DIR}" "${INSTALL_DIR}/projects" "${DATA_DIR}" /etc/supervisor-panel

echo "[3/6] 下载升级包 (${PACKAGE_NAME})..."
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT
echo "[3/6] 下载地址: ${PACKAGE_URL}"
echo "[3/6] 保存到: ${TMP_DIR}/${PACKAGE_NAME}"
curl -fL "${PACKAGE_URL}" -o "${TMP_DIR}/${PACKAGE_NAME}"
tar -xzf "${TMP_DIR}/${PACKAGE_NAME}" -C "${TMP_DIR}"
if [[ ! -f "${TMP_DIR}/supervisor-panel" ]]; then
  echo "升级包缺少 supervisor-panel 二进制文件: ${PACKAGE_URL}" >&2
  exit 1
fi

echo "[4/6] 备份当前程序..."
BACKUP_PATH="${BIN_PATH}.bak.$(date +%Y%m%d%H%M%S)"
cp -f "${BIN_PATH}" "${BACKUP_PATH}"
chmod 755 "${BACKUP_PATH}"
echo "[4/6] 备份文件: ${BACKUP_PATH}"

echo "[5/6] 安装新版本..."
install -m 755 "${TMP_DIR}/supervisor-panel" "${BIN_PATH}"
chmod 755 "${BIN_PATH}"

echo "[6/6] 重启服务..."
systemctl daemon-reload
if ! systemctl restart supervisor-panel; then
  echo "重启失败，尝试回滚到旧版本..." >&2
  cp -f "${BACKUP_PATH}" "${BIN_PATH}"
  chmod 755 "${BIN_PATH}"
  systemctl restart supervisor-panel
  echo "已回滚到旧版本，升级未生效。" >&2
  exit 1
fi

systemctl --no-pager --full status supervisor-panel | sed -n '1,12p'
echo "升级完成。"
echo "当前版本包来源: ${PACKAGE_URL}"
echo "配置文件未变更: ${ENV_FILE}"
echo "管理员账号与业务数据保持不变。"
