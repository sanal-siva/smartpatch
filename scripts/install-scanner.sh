#!/usr/bin/env bash
# The same Grype version/checksums as the community SONiC SBOM build tool.
set -euo pipefail
umask 022
SMART_PATCH_GRYPE_VERSION=0.112.0
SMART_PATCH_TOOL_DIR=${1:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.tools"}
case "$(uname -m)" in
  x86_64) SMART_PATCH_ARCH=amd64; SMART_PATCH_SHA256=acb14a030010fe9bdb9594b4ae108d9d14ef2f926d936aa0916dc62c89c058ea ;;
  aarch64|arm64) SMART_PATCH_ARCH=arm64; SMART_PATCH_SHA256=7fdeccf065965cc59386c656e5fcc1eb1bdf820e2433000bca7f010b8e6da155 ;;
  *) echo 'Grype installer supports Linux amd64/arm64 only.' >&2; exit 1 ;;
esac
[[ "$(uname -s)" == Linux ]] || { echo 'Linux is required.' >&2; exit 1; }
mkdir -p "$SMART_PATCH_TOOL_DIR"
SMART_PATCH_DOWNLOAD=$(mktemp -d)
trap 'rm -rf "$SMART_PATCH_DOWNLOAD"' EXIT
curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
  "https://github.com/anchore/grype/releases/download/v${SMART_PATCH_GRYPE_VERSION}/grype_${SMART_PATCH_GRYPE_VERSION}_linux_${SMART_PATCH_ARCH}.tar.gz" \
  --output "$SMART_PATCH_DOWNLOAD/grype.tar.gz"
printf '%s  %s\n' "$SMART_PATCH_SHA256" "$SMART_PATCH_DOWNLOAD/grype.tar.gz" | sha256sum --check --status
tar -xzf "$SMART_PATCH_DOWNLOAD/grype.tar.gz" -C "$SMART_PATCH_DOWNLOAD" grype
install -m 0755 "$SMART_PATCH_DOWNLOAD/grype" "$SMART_PATCH_TOOL_DIR/grype"
"$SMART_PATCH_TOOL_DIR/grype" version
