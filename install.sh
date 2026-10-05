#!/usr/bin/env bash
# ==============================================================================
# Orbit Enterprise Server - Automated Production Provisioner
# ==============================================================================

set -euo pipefail

###################################
# CONSTANTS & DIRECTORIES
###################################
APP_DIR="/opt/orbit-server"
VAR_DIR="/var/lib/orbit-server"
LOG_DIR="/var/log/orbit"
SERVICE_FILE="/etc/systemd/system/orbit-server.service"
# Determine sysconfig / default path according to OS family
if [ -d "/etc/sysconfig" ]; then
    SYSCONFIG_FILE="/etc/sysconfig/orbit-server"
else
    SYSCONFIG_FILE="/etc/default/orbit-server"
fi
LOGROTATE_FILE="/etc/logrotate.d/orbit-server"

# ANSI Terminal Colors
COLOR_RESET="\033[0m"
COLOR_INFO="\033[38;5;39m"
COLOR_SUCCESS="\033[38;5;48m"
COLOR_WARN="\033[38;5;214m"
COLOR_ERROR="\033[38;5;196m"

log_info() {
    printf "${COLOR_INFO}[INFO]${COLOR_RESET} %s\n" "$1"
}

log_success() {
    printf "${COLOR_SUCCESS}[OK]${COLOR_RESET} %s\n" "$1"
}

log_warn() {
    printf "${COLOR_WARN}[WARN]${COLOR_RESET} %s\n" "$1"
}

log_error() {
    printf "${COLOR_ERROR}[ERROR]${COLOR_RESET} %s\n" "$1" >&2
}

###################################
# PRIVILEGE VALIDATION
###################################
if [ "$(id -u)" -ne 0 ]; then
    log_error "This script must be executed with root privileges (e.g., via sudo)."
    exit 1
fi

printf "\n"
printf "  =======================================================\n"
printf "   Orbit Enterprise Server - System Provisioning          \n"
printf "  =======================================================\n\n"

###################################
# SYSTEM USER PROVISIONING
###################################
log_info "Ensuring system group and dedicated service user exist..."
if ! getent group orbit >/dev/null 2>&1; then
    groupadd -r orbit
    log_success "Created system group: orbit"
fi

if ! getent passwd orbit >/dev/null 2>&1; then
    useradd -r -g orbit -s /sbin/nologin -d "${VAR_DIR}" -c "Orbit Enterprise Service" orbit
    log_success "Created system user: orbit"
fi

###################################
# FILESYSTEM HIERARCHY INITIALIZATION
###################################
log_info "Creating required directory hierarchy..."
mkdir -p "${APP_DIR}"
mkdir -p "${VAR_DIR}/nodes"
mkdir -p "${VAR_DIR}/tasks"
mkdir -p "${LOG_DIR}"

###################################
# PYTHON VIRTUAL ENVIRONMENT
###################################
log_info "Configuring Python virtual environment in ${APP_DIR}/venv..."
if [ ! -d "${APP_DIR}/venv" ]; then
    (umask 022 && python3 -m venv "${APP_DIR}/venv")
    log_success "Virtual environment initialized."
fi

log_info "Installing / updating runtime dependencies..."
(umask 022 && "${APP_DIR}/venv/bin/pip" install --upgrade pip --no-cache-dir)
(umask 022 && "${APP_DIR}/venv/bin/pip" install --no-cache-dir -r "${APP_DIR}/requirements.txt")
log_success "Python package installation completed."

###################################
# LOGROTATION CONFIGURATION
###################################
log_info "Configuring logrotate policy..."
cat << EOF > "${LOGROTATE_FILE}"
/var/log/orbit/*.log {
    daily
    rotate 14
    missingok
    nocompress
    notifempty
    copytruncate
    create 0640 orbit orbit
}
EOF
chmod 0644 "${LOGROTATE_FILE}"

###################################
# RUNTIME ENVIRONMENT FILE
###################################
if [ ! -f "${SYSCONFIG_FILE}" ]; then
    log_info "Generating environment configuration: ${SYSCONFIG_FILE}..."
    WORKERS_CALCULATED=$(( $(nproc) + 1 ))
    RANDOM_API_TOKEN=$(openssl rand -base64 32)
    RANDOM_JWT_SECRET=$(openssl rand -base64 32)

    cat << EOF > "${SYSCONFIG_FILE}"
# ==========================================
# ORBIT ENTERPRISE SERVER CONFIGURATION
# ==========================================

# --- NETWORKING ---
# Listen interface (127.0.0.1 recommended if behind Apache/Nginx reverse proxy)
ORBIT_HOST=0.0.0.0

# Uvicorn listener port
ORBIT_PORT=8000

# Subdirectory path context if reverse proxy does not terminate at root (/)
ORBIT_ROOT_PATH=

# --- SYSTEM ---
# Number of running processes (CPUs + 1)
ORBIT_WORKERS=${WORKERS_CALCULATED}

# --- SECURITY ---
# Master API authentication token for agents
ORBIT_API_TOKEN=${RANDOM_API_TOKEN}
# Session encryption secret
ORBIT_JWT_SECRET=${RANDOM_JWT_SECRET}

# --- DASHBOARD & RETENTION POLICIES ---
# Maximum rows displayed in the 'Global Execution Audit Log'
ORBIT_MAX_GLOBAL_RESULTS=30

# Maximum security event entries stored
ORBIT_MAX_SECURITY_EVENTS=200

# Log retention for agent task results (*_*_result.json) in days (0 to disable)
ORBIT_RESULTS_RETENTION_DAYS=30

# Days without communication before a node is marked 'Offline'
ORBIT_OFFLINE_THRESHOLD_DAYS=30
EOF
    chmod 0600 "${SYSCONFIG_FILE}"
    log_success "Generated new system configuration with secure random secrets."
else
    log_info "Existing ${SYSCONFIG_FILE} detected. Keeping current secrets and settings."
fi

###################################
# SYSTEM SECURITY & PERMISSIONS
###################################
log_info "Applying restrictive system permissions (Least Privilege)..."

# Source code tree
chown -R root:orbit "${APP_DIR}"
find "${APP_DIR}" -type d -exec chmod o=,u=rwx,g=rx {} +
find "${APP_DIR}" -type f -exec chmod o=,u+rw,g+r {} +
chmod 750 "${APP_DIR}/install.sh" 2>/dev/null || true
chmod -R g+rX "${APP_DIR}/venv"

# Data store (/var/lib/orbit-server)
chown -R orbit:orbit "${VAR_DIR}"
chmod 0700 "${VAR_DIR}"

# Logging directory (/var/log/orbit)
chown -R orbit:orbit "${LOG_DIR}"
chmod 0750 "${LOG_DIR}"

log_success "Filesystem permissions applied."

###################################
# SYSTEMD SERVICE DEPLOYMENT
###################################
log_info "Deploying systemd service unit..."
cat << EOF > "${SERVICE_FILE}"
[Unit]
Description=Orbit Enterprise Server (FastAPI)
After=network.target

[Service]
User=orbit
Group=orbit
WorkingDirectory=${APP_DIR}

Environment="ORBIT_HOST=127.0.0.1"
Environment="ORBIT_PORT=8000"
Environment="ORBIT_WORKERS=2"
EnvironmentFile=-${SYSCONFIG_FILE}

# Gunicorn orchestrating async Uvicorn workers
ExecStart=${APP_DIR}/venv/bin/gunicorn main:app \\
  --workers \${ORBIT_WORKERS} \\
  --worker-class uvicorn.workers.UvicornWorker \\
  --bind \${ORBIT_HOST}:\${ORBIT_PORT} \\
  --access-logfile - \\
  --error-logfile -

# Service Logging
StandardOutput=append:${LOG_DIR}/orbit-server.log
StandardError=append:${LOG_DIR}/orbit-error.log
Restart=always
RestartSec=5

# Security Hardening Directives
ProtectSystem=full
ProtectHome=true
ReadOnlyPaths=${APP_DIR}
ReadWritePaths=${VAR_DIR} ${LOG_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

chmod 0644 "${SERVICE_FILE}"

systemctl daemon-reload
systemctl enable orbit-server.service
log_success "Service unit installed and enabled."

###################################
# FIREWALLD CONFIGURATION
###################################
# Obtener el puerto configurado (o usar 8000 por defecto si no está definido)
if command -v firewall-cmd >/dev/null 2>&1; then
    if systemctl is-active --quiet firewalld; then
        log_info "firewalld is active. Authorizing TCP port 8000..."
        firewall-cmd --permanent --add-port="8000/tcp" >/dev/null
        firewall-cmd --reload >/dev/null
        log_success "Port 8000/tcp opened and firewall rules reloaded."
    else
        log_warn "firewalld is installed but not currently running. Skipping port activation."
    fi
else
    log_info "firewalld not detected on this system. Skipping firewall configuration."
fi

printf "\n"
printf "==========================================================================\n"
printf " ${COLOR_SUCCESS}[SUCCESS]${COLOR_RESET} Orbit Enterprise Server has been successfully provisioned.\n"
printf " ------------------------------------------------------------------------\n"
printf " Start service:        systemctl start orbit-server\n"
printf " Check service health: systemctl status orbit-server\n"
printf " View live logs:       tail -f ${LOG_DIR}/orbit-server.log\n"
printf " Configuration file:   ${SYSCONFIG_FILE}\n"
printf "==========================================================================\n\n"