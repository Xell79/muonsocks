#!/bin/sh
set -eu

# install.sh - Automatic installer and updater for muonsocks daemon
#
# Usage:
#   sudo ./install.sh           # Install or update muonsocks
#   sudo ./install.sh --update  # Pull latest git commit, rebuild, and restart

INSTALL_BIN="/usr/local/bin/muonsocks"
SERVICE_FILE="/etc/systemd/system/muonsocks.service"
DEFAULT_CONFIG="/etc/default/muonsocks"
SERVICE_USER="muonsocks"

log() {
    printf "[*] %s\n" "$1"
}

err() {
    printf "[!] Error: %s\n" "$1" >&2
    exit 1
}

# Require root privileges
if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (or with sudo)."
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Check for --update / update flag
DO_GIT_PULL=0
for arg in "$@"; do
    case "$arg" in
        --update|update|-u)
            DO_GIT_PULL=1
            ;;
        --help|-h)
            printf "Usage: %s [--update]\n" "$0"
            printf "  --update  Pull latest git commits, rebuild, and restart service\n"
            exit 0
            ;;
    esac
done

if [ "$DO_GIT_PULL" -eq 1 ]; then
    if [ -d ".git" ] && command -v git >/dev/null 2>&1; then
        log "Pulling latest changes from git repository..."
        git pull --ff-only || log "Warning: git pull failed, building current local tree"
    else
        log "Not inside a git repository; skipping git pull"
    fi
fi

# Verify build toolchain
command -v make >/dev/null 2>&1 || err "make is not installed."
command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1 || err "C compiler (cc/gcc/clang) not found."

# Build muonsocks
log "Building muonsocks with security hardening..."
make clean
make

# Run regression tests if python3 is available
if command -v python3 >/dev/null 2>&1 && [ -f "test_security.py" ]; then
    log "Running regression test suite..."
    make test
fi

# Ensure service user exists
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    log "Creating system user '$SERVICE_USER'..."
    useradd -r -s /usr/sbin/nologin -d /nonexistent -M "$SERVICE_USER" 2>/dev/null || \
    useradd -r -s /bin/false -d /nonexistent -M "$SERVICE_USER" 2>/dev/null || \
    log "User '$SERVICE_USER' could not be created automatically; check system users"
fi

# Install binary
log "Installing binary to $INSTALL_BIN..."
install -d "$(dirname "$INSTALL_BIN")"
install -m 755 muonsocks "$INSTALL_BIN"

# Install default config if not present
if [ ! -f "$DEFAULT_CONFIG" ]; then
    log "Installing default config to $DEFAULT_CONFIG..."
    install -d "$(dirname "$DEFAULT_CONFIG")"
    if [ -f "muonsocks.default" ]; then
        install -m 644 muonsocks.default "$DEFAULT_CONFIG"
    else
        cat << 'EOF' > "$DEFAULT_CONFIG"
# Configuration options for muonsocks SOCKS proxy daemon
MUONSOCKS_OPTS="-p 1080 -v"
EOF
        chmod 644 "$DEFAULT_CONFIG"
    fi
else
    log "Keeping existing configuration at $DEFAULT_CONFIG"
fi

# Install systemd service if systemd is active
if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
    log "Installing systemd service to $SERVICE_FILE..."
    if [ -f "muonsocks.service" ]; then
        install -m 644 muonsocks.service "$SERVICE_FILE"
    fi
    log "Reloading systemd daemon..."
    systemctl daemon-reload
    log "Enabling and restarting muonsocks.service..."
    systemctl enable muonsocks.service
    systemctl restart muonsocks.service

    # Check status
    if systemctl is-active --quiet muonsocks.service; then
        log "muonsocks.service is active and running."
    else
        log "Warning: muonsocks.service failed to start. Check: journalctl -u muonsocks.service"
    fi
fi

log "Installation/update complete!"
log "Edit $DEFAULT_CONFIG to change options (e.g. add -U user -P pass), then run: systemctl restart muonsocks"
