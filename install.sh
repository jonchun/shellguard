#!/bin/sh
set -e

REPO="jonchun/shellguard"
INSTALL_DIR="${SHELLGUARD_INSTALL_DIR:-/usr/local/bin}"

main() {
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) err "unsupported architecture: $arch" ;;
    esac

    case "$os" in
        linux|darwin) ;;
        *) err "unsupported OS: $os" ;;
    esac

    if [ -z "$SHELLGUARD_VERSION" ]; then
        version="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | sed 's/.*"v\(.*\)".*/\1/')"
        if [ -z "$version" ]; then
            err "failed to determine latest version"
        fi
    else
        version="${SHELLGUARD_VERSION#v}"
    fi

    archive="shellguard_${os}_${arch}.tar.gz"
    url="https://github.com/${REPO}/releases/download/v${version}/${archive}"

    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' EXIT

    log "downloading shellguard v${version} for ${os}/${arch}"
    curl -fsSL "$url" -o "${tmpdir}/${archive}"

    log "extracting to ${INSTALL_DIR}"
    tar -xzf "${tmpdir}/${archive}" -C "$tmpdir"

    if [ -w "$INSTALL_DIR" ]; then
        mv "${tmpdir}/shellguard" "${INSTALL_DIR}/shellguard"
    else
        log "elevated permissions required for ${INSTALL_DIR}"
        sudo mv "${tmpdir}/shellguard" "${INSTALL_DIR}/shellguard"
    fi
    chmod +x "${INSTALL_DIR}/shellguard"

    log "installed shellguard v${version} to ${INSTALL_DIR}/shellguard"
}

log() { printf '%s\n' "$1" >&2; }
err() { log "error: $1"; exit 1; }

main
