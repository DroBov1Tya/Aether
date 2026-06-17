#!/usr/bin/env bash
set -euo pipefail

# ──────────────────────────────────────────────────────────────
#  Aether Agent - Installer
#  Auto-detects OS / architecture, installs system deps + Rust
#   + CLI tools (rustscan, whatweb, hxn) via Cargo
# ──────────────────────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════════
#  Colours / Symbols
# ═══════════════════════════════════════════════════════════════
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ═══════════════════════════════════════════════════════════════
#  Progress-bar helpers
# ═══════════════════════════════════════════════════════════════
TOTAL_STEPS=0
CURRENT_STEP=0

print_progress_bar() {
    local current=$1
    local percent=$(( current * 100 / TOTAL_STEPS ))
    local filled=$(( current * 30 / TOTAL_STEPS ))
    local empty=$(( 30 - filled ))

    local bar=""
    for (( i = 0; i < filled; i++ )); do bar+="█"; done
    for (( i = 0; i < empty; i++ )); do bar+="░"; done

    printf "${BLUE}[%s] %3d%%${NC}\n" "$bar" "$percent" >&2
}

step() {
    CURRENT_STEP=$(( CURRENT_STEP + 1 ))
    print_progress_bar "$CURRENT_STEP"
    echo -e "   ${GREEN}✔${NC} $1"
}

header() {
    echo ""
    local ver
    ver=$(grep '^version' Cargo.toml | head -1 | grep -oP '"\K[^"]+')
    printf "${BOLD}${CYAN}╔══════════════════════════════════════════════════╗${NC}\n"
    printf "${BOLD}${CYAN}║  AETHER AGENT INSTALLER v%s.${NC}\n" "$ver"
    printf "${BOLD}${CYAN}║%60s║${NC}\n" ""
    printf "${BOLD}${CYAN}╚══════════════════════════════════════════════════╝${NC}\n"
    echo ""
}

info()   { echo -e "   ${DIM}[INFO]${NC} $1"; }
warn()   { echo -e "   ${YELLOW}[WARN]${NC} $1" >&2; }
error()  { echo -e "   ${RED}[ERROR]${NC} $1" >&2; exit 1; }

# ═══════════════════════════════════════════════════════════════
#  OS / Arch detection
# ═══════════════════════════════════════════════════════════════
detect_os() {
    if [[ "${OSTYPE:-}" == "darwin"* ]]; then
        OS="macos"
        PKG_MANAGER="brew"
    elif [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS="${ID:-linux}"
        PKG_MANAGER="apt"
    else
        OS="linux"
        PKG_MANAGER="apt"
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  RUST_ARCH=x86_64; MACOS_TARGET="" ;;
        aarch64) RUST_ARCH=aarch64; MACOS_TARGET="" ;;
        arm64)   RUST_ARCH=aarch64; MACOS_TARGET="apple-darwin" ;;
        *)       error "Unsupported architecture: $ARCH" ;;
    esac

    info "OS           : ${BOLD}${OS^^}${NC}  (${ARCH})"
    info "Package Mgr  : ${BOLD}${PKG_MANAGER}${NC}"
    info "Rust target  : ${BOLD}${RUST_ARCH}${NC}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════
#  Pre-flight checks
# ═══════════════════════════════════════════════════════════════
check_cmd() {
    command -v "$1" &>/dev/null && return 0 || return 1
}

check_prereqs() {
    echo " ┌─ Checking prerequisites …"
    MISSING=()

    check_cmd curl    || MISSING+=(curl)
    check_cmd bash     || MISSING+=(bash)

    if [[ ${#MISSING[@]} -gt 0 ]]; then
        for tool in "${MISSING[@]}"; do
            warn "Missing: $tool (will be installed by package manager)"
        done
    else
        info "All prerequisites present."
    fi
}

# ═══════════════════════════════════════════════════════════════
#  Package installation
# ═══════════════════════════════════════════════════════════════
install_macos_deps() {
    check_cmd brew || error "Homebrew is required on macOS. Install from https://brew.sh"

    info "Updating brew …"
    brew update

    local deps=(
        nmap             # network scanner
        git              # rust clone / cargo
    )

    info "brew install: ${deps[*]}"
    brew install "${deps[@]}" || error "brew install failed"
    step "System packages  (macOS)"
}

install_linux_deps() {
    check_cmd apt-get || {
        info "apt-get not found — updating package lists …"
        sudo apt-get update -y || error "Could not update apt repos"
    }

    local deps=(
        build-essential    # gcc, make, etc.
        curl
        git
        nmap               # network scanner
    )

    info "apt install: ${deps[*]}"
    sudo apt-get install -y "${deps[@]}" || error "apt install failed"
    step "System packages  (Linux)"
}

# ═══════════════════════════════════════════════════════════════
#  Rust installation via rustup
# ═══════════════════════════════════════════════════════════════
install_rust() {
    if check_cmd rustc && check_cmd cargo; then
        local rust_ver cargo_ver
        rust_ver=$(rustc --version 2>/dev/null || echo "unknown")
        cargo_ver=$(cargo --version 2>/dev/null || echo "unknown")
        info "$rust_ver | $cargo_ver"
        info "Rust toolchain already installed ✓"
        return 0
    fi

    echo ""
    info "Installing Rust via rustup …"

    # Download rustup installer
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
         -o /tmp/rustup-init.sh 2>/dev/null || error "Failed to download rustup installer"

    # Try Linux first, fallback to macOS
    sh /tmp/rustup-init.sh -y \
        --no-modify-path \
        --default-toolchain stable \
        --target "${RUST_ARCH}-unknown-linux-gnu" 2>/dev/null \
        || sh /tmp/rustup-init.sh -y \
            --no-modify-path \
            --default-toolchain stable \
            --target "${RUST_ARCH}-apple-darwin" 2>/dev/null \
        || error "rustup installation failed"

    rm -f /tmp/rustup-init.sh

    # Source the environment for current shell
    if [[ -f "$HOME/.cargo/env" ]]; then
        source "$HOME/.cargo/env"
    fi

    step "Rust toolchain  (stable)"
}

# ═══════════════════════════════════════════════════════════════
#  Cargo CLI tools
# ═══════════════════════════════════════════════════════════════
install_cli_tools() {
    echo ""
    info "Installing CLI tools via Cargo …"

    # rustscan — required
    if ! cargo install rustscan 2>/dev/null; then
        warn "rustscan not installed (may not exist on crates.io)"
    fi
    step "CLI tools  (cargo install)"

    # Optional tools — warn but don't abort
    for tool in whatweb hxn; do
        if ! cargo install "$tool" 2>/dev/null; then
            warn "$tool not installed (may not exist on crates.io)"
        fi
    done
}

# ═══════════════════════════════════════════════════════════════
#  Verification
# ═══════════════════════════════════════════════════════════════
verify_installation() {
    echo ""
    echo " ┌───────── Verification ──────────────────────────"

    if check_cmd rustc; then
        info "rustc   : $(rustc --version 2>/dev/null)"
    else
        warn "rustc   not found"
    fi

    if check_cmd cargo; then
        info "cargo   : $(cargo --version 2>/dev/null)"
    else
        warn "cargo   not found"
    fi

    if check_cmd nmap; then
        info "nmap    : $(nmap --version | head -1)"
    else
        warn "nmap    not found"
    fi

    if check_cmd rustscan; then
        info "rustscan: OK"
    else
        warn "rustscan not found"
    fi

    echo " └──────────────────────────────────────────────────"
}

# ═══════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════
main() {
    header

    echo " ┌─ System detection …"
    detect_os
    check_prereqs

    # Decide total steps for progress bar
    TOTAL_STEPS=4
    ! { check_cmd rustc && check_cmd cargo; } && TOTAL_STEPS=5
    [[ "$PKG_MANAGER" == "brew" ]] || \
    [[ "$PKG_MANAGER" == "apt"   ]] || error "Unknown package manager: $PKG_MANAGER"

    echo ""
    echo -e "  ${BOLD}[$(date +'%H:%M:%S')] Beginning installation …${NC}"
    echo ""

    # Step 1: System deps
    if [[ "$PKG_MANAGER" == "brew" ]]; then
        install_macos_deps
    else
        install_linux_deps
    fi

    # Step 2: Rust toolchain
    install_rust
    source "$HOME/.cargo/env" 2>/dev/null || true

    # Step 3: CLI tools via cargo
    install_cli_tools

    # Step 4: Verification
    verify_installation

    echo ""
    echo -e "   ${GREEN}${BOLD}✓ Installation complete!${NC}"
    echo ""
    echo -e "  To use:"
    echo -e "     ${DIM}cd agent && cargo run --release${NC}"
    echo ""
}

main "$@"
