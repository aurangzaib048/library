#!/usr/bin/env bash
# install-tools.sh - Install crane and cosign from sbomify/sbom-tools
#
# The library uses the same tool builds as sbomify-action: the "sigstore"
# bundle from https://github.com/sbomify/sbom-tools, built from source and
# published with SLSA build provenance. The release is pinned in
# .sbom-tools-version at the repository root, and the archive is verified
# against its provenance (with `gh attestation verify`) before anything is
# unpacked.
#
# Usage:
#   ./scripts/install-tools.sh                 # install into .tools/, print the bin dir
#   eval "$(./scripts/install-tools.sh --env)" # also put it on PATH in this shell
#   ./scripts/install-tools.sh --dir /opt/sbom-tools --version v26.11.1
#
# On GitHub Actions the bin dir is appended to $GITHUB_PATH automatically.
#
# Requires: gh (authenticated, or GH_TOKEN set), tar, uname

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

TOOLS_REPO="sbomify/sbom-tools"
SIGNER_WORKFLOW="${TOOLS_REPO}/.github/workflows/build.yml"
BUNDLE="sigstore"

install_dir="${REPO_ROOT}/.tools"
version=""
print_env=false

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

log() {
    echo "[INFO] $*" >&2
}

usage() {
    sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)
            [[ $# -lt 2 ]] && die "--dir requires an argument"
            install_dir="$2"
            shift 2
            ;;
        --version)
            [[ $# -lt 2 ]] && die "--version requires an argument"
            version="$2"
            shift 2
            ;;
        --env)
            print_env=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1"
            ;;
    esac
done

if [[ -z "$version" ]]; then
    [[ -f "${REPO_ROOT}/.sbom-tools-version" ]] || die "Missing ${REPO_ROOT}/.sbom-tools-version"
    version="$(tr -d '[:space:]' < "${REPO_ROOT}/.sbom-tools-version")"
fi
[[ -n "$version" ]] || die "No sbom-tools version given"

command -v gh >/dev/null 2>&1 || die "gh is required to download and verify sbom-tools (https://cli.github.com)"

case "$(uname -m)" in
    x86_64|amd64)  arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "Unsupported architecture: $(uname -m)" ;;
esac

[[ "$(uname -s)" == "Linux" ]] || die "sbom-tools publishes Linux builds only (found $(uname -s))"

archive="${BUNDLE}-linux-${arch}.tar.gz"
bin_dir="${install_dir}/bin"
stamp="${install_dir}/.installed"

emit() {
    if [[ -n "${GITHUB_PATH:-}" ]]; then
        echo "$bin_dir" >> "$GITHUB_PATH"
    fi
    if [[ "$print_env" == true ]]; then
        printf 'export PATH=%q:"$PATH"\n' "$bin_dir"
    else
        echo "$bin_dir"
    fi
}

# Already installed at this version?
if [[ -f "$stamp" && "$(<"$stamp")" == "${version} ${archive}" \
    && -x "${bin_dir}/crane" && -x "${bin_dir}/cosign" ]]; then
    log "sbom-tools ${version} (${BUNDLE}) already installed in ${install_dir}"
    emit
    exit 0
fi

work_dir="$(mktemp -d -t sbom-tools.XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

log "Downloading ${archive} from ${TOOLS_REPO}@${version}"
gh release download "$version" \
    --repo "$TOOLS_REPO" \
    --pattern "$archive" \
    --pattern "${archive}.sigstore.json" \
    --dir "$work_dir"

log "Verifying build provenance"
gh attestation verify "${work_dir}/${archive}" \
    --bundle "${work_dir}/${archive}.sigstore.json" \
    --repo "$TOOLS_REPO" \
    --signer-workflow "$SIGNER_WORKFLOW" \
    --source-ref "refs/tags/${version}" \
    --deny-self-hosted-runners >/dev/null \
    || die "Provenance verification failed for ${archive} (${version})"

mkdir -p "${work_dir}/unpacked"
tar -xzf "${work_dir}/${archive}" -C "${work_dir}/unpacked"

# bundle.toml says where the executables live; don't assume the layout
manifest="${work_dir}/unpacked/bundle.toml"
[[ -f "$manifest" ]] || die "${archive} has no bundle.toml"
bundle_bin=$(sed -nE 's/^bin_dirs = \["([^"]+)".*/\1/p' "$manifest")
[[ -n "$bundle_bin" ]] || die "Could not read bin_dirs from bundle.toml"

for tool in crane cosign; do
    [[ -x "${work_dir}/unpacked/${bundle_bin}/${tool}" ]] || die "${archive} does not provide ${tool}"
done

# Only replace what this script owns, never the whole --dir
rm -rf "$bin_dir"
mkdir -p "$bin_dir"
cp "${work_dir}/unpacked/${bundle_bin}/"* "$bin_dir/"
cp "$manifest" "${install_dir}/bundle.toml"
echo "${version} ${archive}" > "$stamp"

log "Installed $("${bin_dir}/crane" version) crane and $("${bin_dir}/cosign" version 2>/dev/null \
    | sed -nE 's/^GitVersion: *//p') cosign into ${bin_dir}"
emit
