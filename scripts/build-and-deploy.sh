#!/usr/bin/env bash
# 一键:用 ko 多架构构镜像 + 推 registry + apply 所有 config 到当前 kubectl 集群。
#
# 用法:
#   scripts/build-and-deploy.sh ghcr.io/coldzerofear           # 用 GHCR
#   scripts/build-and-deploy.sh build-harbor.alauda.cn/zjrcu   # 用内部 Harbor
#
# 前置依赖(执行人本地装好):
#   - go 1.25+
#   - ko (go install github.com/google/ko@latest)
#   - kubectl(已 kubeconfig 到目标集群)
#   - 已经 ko login / docker login 过目标 registry

set -euo pipefail

REGISTRY="${1:?usage: $0 <registry-prefix>  e.g. ghcr.io/coldzerofear}"

# 多架构构建。CI 跑过 release.yml 走 buildx 也行,这里走 ko 因为是 sigstore 原生工具
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"

GIT_HASH="$(git rev-parse HEAD)"
GIT_VERSION="$(git describe --tags --always --dirty)"
GIT_TREESTATE="clean"
[ -n "$(git diff --stat)" ] && GIT_TREESTATE="dirty"

LDFLAGS="-buildid= \
  -X sigs.k8s.io/release-utils/version.gitVersion=${GIT_VERSION} \
  -X sigs.k8s.io/release-utils/version.gitCommit=${GIT_HASH} \
  -X sigs.k8s.io/release-utils/version.gitTreeState=${GIT_TREESTATE} \
  -X sigs.k8s.io/release-utils/version.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

export KO_DOCKER_REPO="${REGISTRY}"
export GIT_HASH GIT_VERSION LDFLAGS

echo "============================================================"
echo " policy-controller (zjrcu-gm)  build + deploy"
echo "------------------------------------------------------------"
echo " Registry:  ${KO_DOCKER_REPO}"
echo " Version:   ${GIT_VERSION}"
echo " Commit:    ${GIT_HASH}"
echo " Platforms: ${PLATFORMS}"
echo "============================================================"

# ko apply: 构建 + push + 替换 config/ 里的 ko://... 为真实 image ref + kubectl apply
ko apply \
  --bare \
  --platform="${PLATFORMS}" \
  --tags="${GIT_VERSION},${GIT_HASH}" \
  -f config/

echo ""
echo "✓ Deploy complete. Verify:"
echo "  kubectl -n cosign-system get pods"
echo "  kubectl -n cosign-system logs -l role=webhook --tail=50"
echo "  kubectl explain clusterimagepolicy.spec.authorities.gmSignature"
