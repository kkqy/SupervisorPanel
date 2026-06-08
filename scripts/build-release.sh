#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-}"
TARGETS="${TARGETS:-linux/386,linux/amd64,linux/arm,linux/arm64}"
ARM_VARIANT="${ARM_VARIANT:-7}"
OUTPUT_DIR="${OUTPUT_DIR:-dist/releases}"

if [[ -z "${VERSION}" ]]; then
  echo "请设置 VERSION，例如: VERSION=v1.0.0" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_DIR="${ROOT_DIR}/${OUTPUT_DIR}/${VERSION}"
BUILD_ROOT="${ROOT_DIR}/.build-release/${VERSION}"

normalize_goarch() {
  local arch="$1"
  case "${arch}" in
    x86)
      printf '%s' "386"
      ;;
    x64)
      printf '%s' "amd64"
      ;;
    *)
      printf '%s' "${arch}"
      ;;
  esac
}

artifact_arch_name() {
  local goarch="$1"
  case "${goarch}" in
    386)
      printf '%s' "386"
      ;;
    amd64)
      printf '%s' "amd64"
      ;;
    arm)
      printf '%s' "arm"
      ;;
    arm64)
      printf '%s' "arm64"
      ;;
    *)
      printf '%s' "${goarch}"
      ;;
  esac
}

mkdir -p "${RELEASE_DIR}" "${BUILD_ROOT}"

IFS=',' read -r -a target_items <<< "${TARGETS}"

echo "开始构建版本: ${VERSION}"
echo "目标平台: ${TARGETS}"

cd "${ROOT_DIR}"

if ! command -v npm >/dev/null 2>&1; then
  echo "未找到 npm，无法构建 Vue 前端" >&2
  exit 1
fi

echo "构建 Vue 前端..."
(
  cd "${ROOT_DIR}/web"
  if [[ -f package-lock.json ]]; then
    npm ci
  else
    npm install
  fi
  npm run build
)

for raw_target in "${target_items[@]}"; do
  target="${raw_target// /}"
  if [[ -z "${target}" ]]; then
    continue
  fi

  IFS='/' read -r goos raw_arch raw_variant <<< "${target}"
  if [[ -z "${goos}" || -z "${raw_arch}" ]]; then
    echo "无效 TARGETS 项: ${target}" >&2
    exit 1
  fi

  goarch="$(normalize_goarch "${raw_arch}")"
  variant="${raw_variant:-}"
  if [[ "${goarch}" == "arm" && -z "${variant}" ]]; then
    variant="${ARM_VARIANT}"
  fi
  if [[ "${variant}" == v* ]]; then
    variant="${variant#v}"
  fi

  build_dir="${BUILD_ROOT}/${goos}-${goarch}"
  rm -rf "${build_dir}"
  mkdir -p "${build_dir}"

  echo "编译 ${goos}/${goarch}${variant:+/v${variant}}..."
  if [[ "${goarch}" == "arm" ]]; then
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" GOARM="${variant}" \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "${build_dir}/supervisor-panel" ./cmd/supervisor-panel
  else
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
      go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "${build_dir}/supervisor-panel" ./cmd/supervisor-panel
  fi
  cp "${ROOT_DIR}/scripts/upgrade.sh" "${build_dir}/upgrade.sh"
  chmod 755 "${build_dir}/upgrade.sh"

  artifact_arch="$(artifact_arch_name "${goarch}")"
  package_name="supervisor-panel_${VERSION}_${goos}_${artifact_arch}.tar.gz"
  tar -C "${build_dir}" -czf "${RELEASE_DIR}/${package_name}" supervisor-panel upgrade.sh
done

(
  cd "${RELEASE_DIR}"
  sha256sum ./*.tar.gz > SHA256SUMS
)

echo "发布文件已生成: ${RELEASE_DIR}"
echo "可用于下载服务目录: /releases/${VERSION}/"
