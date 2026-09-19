#!/usr/bin/env bash
# 通过 sing-box 使用 Xray 分享链接启动本地代理并探测可用节点。
# 环境变量:
#   PROXY_SHARE_LINKS  分享链接，按行分隔，一个或多个（必填才启用）
#                      支持 vless:// vmess:// trojan:// ss:// hy2://
#   PROXY_TEST_URL     探测目标，默认 https://www.google.com/generate_204
#   PROXY_REQUIRED     true 时探测失败则退出 1
#   PROXY_PORT         本地 mixed 端口（HTTP/SOCKS 共用），默认 7890
#   SINGBOX_VERSION    sing-box 版本，默认 v1.14.1
#   PYTHON_BIN         生成配置用的 Python，默认 python3

set -euo pipefail

if [[ -z "${PROXY_SHARE_LINKS:-}" ]]; then
	echo "[INFO] PROXY_SHARE_LINKS not set, skip sing-box proxy setup"
	exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROXY_DIR="${RUNNER_TEMP:-/tmp}/checkin-proxy"
PROXY_PORT="${PROXY_PORT:-7890}"
PROXY_TEST_URL="${PROXY_TEST_URL:-https://www.google.com/generate_204}"
SINGBOX_VERSION="${SINGBOX_VERSION:-v1.14.1}"
PROXY_REQUIRED="${PROXY_REQUIRED:-false}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

# 失败时按 PROXY_REQUIRED 决定是中断 workflow 还是放行（不设代理继续签到）
fail() {
	echo "[FAILED] $1"
	if [[ "${PROXY_REQUIRED}" == "true" ]]; then
		exit 1
	fi
	exit 0
}

mkdir -p "${PROXY_DIR}"
cd "${PROXY_DIR}"

# 分享链接里含密码，落盘的临时文件收紧权限并用完即删
echo "[INFO] Generating sing-box config from PROXY_SHARE_LINKS..."
umask 077
printf '%s' "${PROXY_SHARE_LINKS}" > links.txt
if ! (cd "${REPO_ROOT}" && "${PYTHON_BIN}" -m utils.singbox \
	--links-file "${PROXY_DIR}/links.txt" \
	--port "${PROXY_PORT}" \
	--test-url "${PROXY_TEST_URL}" \
	-o "${PROXY_DIR}/config.json"); then
	rm -f links.txt
	fail "Failed to build sing-box config from PROXY_SHARE_LINKS"
fi
rm -f links.txt

echo "[INFO] Downloading sing-box ${SINGBOX_VERSION}..."
VERSION="${SINGBOX_VERSION#v}"
ARCHIVE="sing-box-${VERSION}-linux-amd64.tar.gz"
if ! curl --retry 3 --retry-delay 5 --retry-all-errors -fsSL -o "${ARCHIVE}" \
	"https://github.com/SagerNet/sing-box/releases/download/${SINGBOX_VERSION}/${ARCHIVE}"; then
	echo "[WARN] Failed to download sing-box ${SINGBOX_VERSION}"
	fail "Failed to download sing-box ${SINGBOX_VERSION}"
fi
tar -xzf "${ARCHIVE}"
SINGBOX_BIN="$(find . -maxdepth 3 -type f -name sing-box -print -quit)"
if [[ -z "${SINGBOX_BIN}" ]]; then
	fail "sing-box binary not found in ${ARCHIVE}"
fi
chmod +x "${SINGBOX_BIN}"

echo "[INFO] Validating sing-box config..."
if ! "${SINGBOX_BIN}" check -c config.json; then
	# 不打印 config.json：里面有节点密码
	fail "sing-box config validation failed"
fi

echo "[INFO] Starting sing-box on 127.0.0.1:${PROXY_PORT}..."
nohup "${SINGBOX_BIN}" run -c config.json > singbox.log 2>&1 &
echo $! > singbox.pid

PROXY_URL="http://127.0.0.1:${PROXY_PORT}"
READY=false
for attempt in $(seq 1 45); do
	if curl -fsS -x "${PROXY_URL}" --max-time 20 "${PROXY_TEST_URL}" -o /dev/null 2>/dev/null; then
		READY=true
		break
	fi
	echo "[INFO] Waiting for proxy health check (${attempt}/45)..."
	sleep 2
done

if [[ "${READY}" != "true" ]]; then
	echo "[FAILED] Proxy health check failed for ${PROXY_TEST_URL}"
	tail -n 30 singbox.log || true
	if [[ -f singbox.pid ]]; then
		kill "$(cat singbox.pid)" 2>/dev/null || true
		rm -f singbox.pid
	fi
	fail "sing-box proxy is not reachable"
fi

echo "[SUCCESS] Proxy is ready: ${PROXY_URL}"
echo "[INFO] Proxy is scoped to CHECKIN_PROXY_URL (browser/python only, not global HTTP_PROXY)"
if [[ -n "${GITHUB_ENV:-}" ]]; then
	echo "CHECKIN_PROXY_URL=${PROXY_URL}" >> "${GITHUB_ENV}"
fi
