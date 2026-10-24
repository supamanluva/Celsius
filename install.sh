#!/usr/bin/env bash
# Full local runtime setup for Debian/Ubuntu-family Linux.
set -Eeuo pipefail

readonly ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly BIN_DIR="$HOME/.local/bin"
readonly UV_VERSION="0.13.5"
readonly NUCLEI_VERSION="3.8.0"
readonly GITLEAKS_VERSION="8.30.1"
readonly TRUFFLEHOG_VERSION="3.99.7"
readonly SEMGREP_VERSION="1.182.1"

export PATH="$BIN_DIR:$HOME/go/bin:$PATH"

tmp_dir=""

log() {
    printf '\n==> %s\n' "$*"
}

die() {
    printf 'install.sh: %s\n' "$*" >&2
    exit 1
}

cleanup() {
    if [[ -n "$tmp_dir" && -d "$tmp_dir" ]]; then
        rm -rf -- "$tmp_dir"
    fi
}
trap cleanup EXIT

usage() {
    cat <<'EOF'
Usage: ./install.sh

Install the complete Celsius local runtime on Debian/Ubuntu-family Linux:
  - Python 3.12 and locked web/dynamic Python dependencies
  - Chromium and its system libraries for JavaScript-rendered scans
  - Nmap, Nuclei, and the Nuclei vulnerability templates
  - Gitleaks, Semgrep, and Trufflehog for source-code scans

Requires internet access, apt-get, and sudo. Existing scanner commands are
preserved. New command-line tools are installed under ~/.local/bin; the
project environment is installed under .venv in this checkout.

Do not run as root. The script uses sudo for system packages only. Nmap OS
fingerprinting still requires root or the recommended Docker deployment.

After installation, run ./run.sh and open http://127.0.0.1:8000.
EOF
}

download() {
    local url="$1"
    local destination="$2"
    curl --fail --location --silent --show-error --retry 3 \
        --proto '=https' --tlsv1.2 --output "$destination" "$url"
}

verify_checksum() {
    local archive="$1"
    local checksum_file="$2"
    local asset="${archive##*/}"
    local expected actual

    expected="$(awk -v asset="$asset" '
        {
            name = $2
            sub(/^\*/, "", name)
            if (name == asset && length($1) == 64 && $1 ~ /^[[:xdigit:]]+$/) {
                print tolower($1)
                exit
            }
        }
    ' "$checksum_file")"
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "no SHA-256 checksum found for $asset"
    actual="$(sha256sum "$archive")"
    actual="${actual%% *}"
    [[ "${actual,,}" == "$expected" ]] || die "SHA-256 verification failed for $asset"
    log "Verified $asset"
}

install_uv() {
    local platform="$1"
    if command -v uv >/dev/null 2>&1; then
        log "uv already available at $(command -v uv)"
        return
    fi

    local work="$tmp_dir/uv"
    local asset="uv-$platform.tar.gz"
    local base="https://github.com/astral-sh/uv/releases/download/$UV_VERSION"
    mkdir -p "$work"
    log "Installing uv $UV_VERSION"
    download "$base/$asset" "$work/$asset"
    download "$base/$asset.sha256" "$work/$asset.sha256"
    verify_checksum "$work/$asset" "$work/$asset.sha256"
    tar -xzf "$work/$asset" -C "$work"
    install -m 0755 "$work/uv-$platform/uv" "$BIN_DIR/uv"
    install -m 0755 "$work/uv-$platform/uvx" "$BIN_DIR/uvx"
    hash -r
}

install_nuclei() {
    local arch="$1"
    if command -v nuclei >/dev/null 2>&1; then
        log "Nuclei already available at $(command -v nuclei)"
        return
    fi

    local work="$tmp_dir/nuclei"
    local asset="nuclei_${NUCLEI_VERSION}_linux_${arch}.zip"
    local sums="nuclei_${NUCLEI_VERSION}_checksums.txt"
    local base="https://github.com/projectdiscovery/nuclei/releases/download/v$NUCLEI_VERSION"
    mkdir -p "$work/extract"
    log "Installing Nuclei $NUCLEI_VERSION"
    download "$base/$asset" "$work/$asset"
    download "$base/$sums" "$work/$sums"
    verify_checksum "$work/$asset" "$work/$sums"
    unzip -q -j "$work/$asset" nuclei -d "$work/extract"
    install -m 0755 "$work/extract/nuclei" "$BIN_DIR/nuclei"
    hash -r
}

install_gitleaks() {
    local arch="$1"
    if command -v gitleaks >/dev/null 2>&1; then
        log "Gitleaks already available at $(command -v gitleaks)"
        return
    fi

    local work="$tmp_dir/gitleaks"
    local asset="gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz"
    local sums="gitleaks_${GITLEAKS_VERSION}_checksums.txt"
    local base="https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION"
    mkdir -p "$work/extract"
    log "Installing Gitleaks $GITLEAKS_VERSION"
    download "$base/$asset" "$work/$asset"
    download "$base/$sums" "$work/$sums"
    verify_checksum "$work/$asset" "$work/$sums"
    tar -xzf "$work/$asset" -C "$work/extract"
    install -m 0755 "$work/extract/gitleaks" "$BIN_DIR/gitleaks"
    hash -r
}

install_trufflehog() {
    local arch="$1"
    if command -v trufflehog >/dev/null 2>&1; then
        log "Trufflehog already available at $(command -v trufflehog)"
        return
    fi

    local work="$tmp_dir/trufflehog"
    local asset="trufflehog_${TRUFFLEHOG_VERSION}_linux_${arch}.tar.gz"
    local sums="trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt"
    local base="https://github.com/trufflesecurity/trufflehog/releases/download/v$TRUFFLEHOG_VERSION"
    mkdir -p "$work/extract"
    log "Installing Trufflehog $TRUFFLEHOG_VERSION"
    download "$base/$asset" "$work/$asset"
    download "$base/$sums" "$work/$sums"
    verify_checksum "$work/$asset" "$work/$sums"
    tar -xzf "$work/$asset" -C "$work/extract"
    install -m 0755 "$work/extract/trufflehog" "$BIN_DIR/trufflehog"
    hash -r
}

install_semgrep() {
    if command -v semgrep >/dev/null 2>&1; then
        log "Semgrep already available at $(command -v semgrep)"
        return
    fi
    log "Installing Semgrep $SEMGREP_VERSION in an isolated uv tool environment"
    UV_TOOL_BIN_DIR="$BIN_DIR" uv tool install --python 3.12 --force "semgrep==$SEMGREP_VERSION"
    hash -r
}

verify_installation() {
    local tool
    for tool in nmap nuclei gitleaks semgrep trufflehog; do
        command -v "$tool" >/dev/null 2>&1 || die "$tool is not discoverable on PATH"
    done

    log "Checking installed tools"
    "$ROOT_DIR/.venv/bin/celsius" --version
    nmap --version
    nuclei -version
    gitleaks version
    SEMGREP_SEND_METRICS=off semgrep --version
    trufflehog --version

    "$ROOT_DIR/.venv/bin/python" - <<'PY'
import fastapi
import multipart
import playwright
import uvicorn
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    page.goto("about:blank")
    browser.close()
print("Celsius web dependencies and Chromium are working.")
PY
}

main() {
    case "${1:-}" in
        -h|--help)
            usage
            return
            ;;
        "") ;;
        *) die "unknown argument: $1 (use --help)" ;;
    esac

    [[ "$(uname -s)" == "Linux" ]] || die "this installer supports Linux; use the manual installation docs on other systems"
    (( EUID != 0 )) || die "run as a normal user, not root; sudo will be requested when needed"
    [[ -f "$ROOT_DIR/pyproject.toml" && -f "$ROOT_DIR/uv.lock" ]] || die "run the installer from a complete Celsius checkout"
    command -v apt-get >/dev/null 2>&1 || die "apt-get is required; use the manual installation docs on this system"
    command -v sudo >/dev/null 2>&1 || die "sudo is required for Nmap and Chromium system libraries"

    local machine uv_platform release_arch gitleaks_arch
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64)
            uv_platform="x86_64-unknown-linux-gnu"
            release_arch="amd64"
            gitleaks_arch="x64"
            ;;
        aarch64|arm64)
            uv_platform="aarch64-unknown-linux-gnu"
            release_arch="arm64"
            gitleaks_arch="arm64"
            ;;
        *) die "unsupported architecture: $machine (supported: x86_64 and arm64)" ;;
    esac

    local packages=(ca-certificates curl unzip python3 python3-venv)
    if ! command -v nmap >/dev/null 2>&1; then
        packages+=(nmap)
    fi

    log "Installing system prerequisites with sudo"
    sudo -v
    sudo apt-get update
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
    mkdir -p "$BIN_DIR"
    tmp_dir="$(mktemp -d)"

    install_uv "$uv_platform"
    uv python install 3.12
    log "Installing Celsius with locked web and dynamic dependencies"
    (cd "$ROOT_DIR" && uv sync --frozen --extra web --extra dynamic --no-dev --python 3.12)

    install_nuclei "$release_arch"
    install_gitleaks "$gitleaks_arch"
    install_trufflehog "$release_arch"
    install_semgrep

    log "Installing Chromium and its system libraries"
    sudo "$ROOT_DIR/.venv/bin/playwright" install-deps chromium
    "$ROOT_DIR/.venv/bin/playwright" install chromium

    log "Installing or updating Nuclei vulnerability templates"
    nuclei -update-templates
    verify_installation

    printf '\nInstallation complete.\n'
    printf 'Start Celsius with: cd %q && ./run.sh\n' "$ROOT_DIR"
    printf 'Then open http://127.0.0.1:8000\n'
    printf 'Add this to your shell PATH for direct CLI tool access: %s\n' "$BIN_DIR"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
