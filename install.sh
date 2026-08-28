#!/bin/sh
set -eu

# install.sh - Installer, uninstaller, and updater for muonsocks
#
# Usage:
#   sudo make install              # Standard installation via Makefile
#   sudo make uninstall            # Uninstallation via Makefile
#   sudo make update               # Pull latest git commit, rebuild, and update
#   make install DESTDIR=/tmp/pkg  # Staged installation for packaging

DESTDIR="${DESTDIR:-}"
prefix="${prefix:-/usr/local}"
bindir="${bindir:-$prefix/bin}"
sysconfdir="${sysconfdir:-/etc}"
systemdunitdir="${systemdunitdir:-/etc/systemd/system}"
SERVICE_USER="${SERVICE_USER:-muonsocks}"
PROG="${PROG:-muonsocks}"

log() {
    printf "[*] %s\n" "$1"
}

err() {
    printf "[!] Error: %s\n" "$1" >&2
    exit 1
}

# Resolve paths
dest_dir="${DESTDIR%/}"
target_bindir="${dest_dir}${bindir}"
target_confdir="${dest_dir}${sysconfdir}/default"
target_unitdir="${dest_dir}${systemdunitdir}"
target_bin="${target_bindir}/${PROG}"
target_conf="${target_confdir}/${PROG}"
target_service="${target_unitdir}/${PROG}.service"

ACTION="install"
DO_GIT_PULL=0

for arg in "$@"; do
    case "$arg" in
        --update|update|-u)
            ACTION="update"
            DO_GIT_PULL=1
            ;;
        --uninstall|uninstall)
            ACTION="uninstall"
            ;;
        --help|-h)
            printf "Usage: %s [OPTIONS]\n\n" "$0"
            printf "Options:\n"
            printf "  --update, -u       Pull latest git commits, rebuild, and restart service\n"
            printf "  --uninstall        Stop service and remove installed files\n"
            printf "  --help, -h         Show this help message\n\n"
            printf "Environment variables (or Make variables):\n"
            printf "  DESTDIR            Staging root directory for packaging (default: empty)\n"
            printf "  prefix             Installation prefix (default: /usr/local)\n"
            printf "  bindir             Binary directory (default: \$prefix/bin)\n"
            printf "  sysconfdir         System config directory (default: /etc)\n"
            printf "  systemdunitdir     Systemd unit directory (default: /etc/systemd/system)\n"
            printf "  SERVICE_USER       System user for the daemon (default: muonsocks)\n"
            exit 0
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ---------------------------------------------------------
# UNINSTALL ACTION
# ---------------------------------------------------------
if [ "$ACTION" = "uninstall" ]; then
    log "Uninstalling $PROG..."

    if [ -z "$DESTDIR" ] && [ "$(id -u)" -eq 0 ]; then
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            log "Stopping and disabling ${PROG}.service..."
            systemctl stop "${PROG}.service" 2>/dev/null || true
            systemctl disable "${PROG}.service" 2>/dev/null || true
        fi
    fi

    if [ -f "$target_service" ]; then
        log "Removing systemd service unit: $target_service"
        rm -f "$target_service"
    fi

    if [ -f "$target_bin" ]; then
        log "Removing binary: $target_bin"
        rm -f "$target_bin"
    fi

    if [ -z "$DESTDIR" ] && [ "$(id -u)" -eq 0 ]; then
        if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            log "Reloading systemd daemon..."
            systemctl daemon-reload 2>/dev/null || true
        fi
    fi

    if [ -f "$target_conf" ]; then
        log "Note: Configuration file '$target_conf' was preserved."
        log "To remove it manually: rm -f $target_conf"
    fi

    log "Uninstallation of $PROG completed."
    exit 0
fi

# ---------------------------------------------------------
# UPDATE ACTION
# ---------------------------------------------------------
if [ "$ACTION" = "update" ]; then
    if [ "$DO_GIT_PULL" -eq 1 ]; then
        if [ -d ".git" ] && command -v git >/dev/null 2>&1; then
            log "Pulling latest changes from git repository..."
            git pull --ff-only || log "Warning: git pull failed, building current local tree"
        else
            log "Not inside a git repository; skipping git pull"
        fi
    fi

    log "Rebuilding $PROG..."
    make clean
    make

    if command -v python3 >/dev/null 2>&1 && [ -f "tests/test_security.py" ]; then
        log "Running regression test suite..."
        make test
    fi
fi

# ---------------------------------------------------------
# INSTALL ACTION
# ---------------------------------------------------------

# If binary is missing, compile it
if [ ! -f "$PROG" ]; then
    log "Binary '$PROG' not found, building..."
    make "$PROG"
fi

# Check permissions for system-wide install when DESTDIR is empty
if [ -z "$DESTDIR" ] && [ "$(id -u)" -ne 0 ]; then
    # If target bindir is not writable, require root
    if [ ! -w "$bindir" ] && [ ! -w "$(dirname "$bindir")" ]; then
        err "Target installation path '$bindir' is not writable. Please run with sudo or as root."
    fi
fi

# Create service system user if running as root on live system
if [ -z "$DESTDIR" ] && [ "$(id -u)" -eq 0 ]; then
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        log "Creating system user '$SERVICE_USER'..."
        useradd -r -s /usr/sbin/nologin -d /nonexistent -M "$SERVICE_USER" 2>/dev/null || \
        useradd -r -s /bin/false -d /nonexistent -M "$SERVICE_USER" 2>/dev/null || \
        log "User '$SERVICE_USER' could not be created automatically; check system users"
    fi
fi

# Install binary
log "Installing binary to $target_bin..."
install -d "$target_bindir"
install -m 755 "$PROG" "$target_bin"

# Install default config if not present
if [ ! -f "$target_conf" ]; then
    log "Installing default config to $target_conf..."
    install -d "$target_confdir"
    if [ -f "${PROG}.default" ]; then
        install -m 644 "${PROG}.default" "$target_conf"
    else
        cat << EOF > "$target_conf"
# Configuration options for muonsocks SOCKS proxy daemon
MUONSOCKS_OPTS="-p 1080 -v"
EOF
        chmod 644 "$target_conf"
    fi
else
    log "Keeping existing configuration at $target_conf"
fi

# Install systemd service unit
if [ -f "${PROG}.service" ]; then
    log "Installing systemd service to $target_service..."
    install -d "$target_unitdir"

    tmp_service="$(mktemp 2>/dev/null || printf '%s' "/tmp/${PROG}.service.$$")"
    sed \
        -e "s|/usr/local/bin/${PROG}|${bindir}/${PROG}|g" \
        -e "s|/etc/default/${PROG}|${sysconfdir}/default/${PROG}|g" \
        -e "s|User=muonsocks|User=${SERVICE_USER}|g" \
        -e "s|Group=muonsocks|Group=${SERVICE_USER}|g" \
        "${PROG}.service" > "$tmp_service"
    install -m 644 "$tmp_service" "$target_service"
    rm -f "$tmp_service"
fi

# Reload and restart systemd service if running on active systemd host as root
if [ -z "$DESTDIR" ] && [ "$(id -u)" -eq 0 ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        log "Reloading systemd daemon..."
        systemctl daemon-reload 2>/dev/null || true
        log "Enabling and restarting ${PROG}.service..."
        systemctl enable "${PROG}.service" 2>/dev/null || true
        systemctl restart "${PROG}.service" 2>/dev/null || true

        if systemctl is-active --quiet "${PROG}.service" 2>/dev/null; then
            log "${PROG}.service is active and running."
        else
            log "Notice: ${PROG}.service installed. Check status with: systemctl status ${PROG}.service"
        fi
    fi
fi

log "Installation complete!"
log "Edit $target_conf to customize configuration options."
