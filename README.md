# Orbit Enterprise Server

[![License](https://img.shields.io/badge/license-AGPLv3-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-brightgreen.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-teal.svg)](https://fastapi.tiangolo.com/)

**Orbit Enterprise Server** is a centralized, lightweight patch management and orchestration platform for Linux server fleets. Built with a decoupled REST architecture using FastAPI, it enables security patch auditing, inventory inspection, update scheduling, and unattended coordination of pending reboots safely and efficiently.

## 📋 Table of Contents

- [Key Features](#-key-features)
- [System Requirements](#-system-requirements)
- [Project Structure & FHS](#-project-structure--fhs)
- [Installation Procedure](#-installation-procedure)
  - [Option A: Quick Bootstrap Installer (Recommended)](#option-a-quick-bootstrap-installer-recommended)
  - [Option B: Manual Git Clone](#option-b-manual-git-clone)
- [System Configuration](#-system-configuration)
  - [Environment Variables (`/etc/sysconfig/orbit-server`)](#environment-variables-etcsysconfigorbit-server)
- [Initial Credentials](#-initial-credentials)
- [Reverse Proxy (Nginx / Apache)](#-reverse-proxy-nginx--apache)
- [License](#-license)
- [Acknowledgments & Development Note](#-acknowledgments--development-note)

## ✨ Key Features

* **Real-Time Vulnerability Auditing:** Detection of security patches categorized by severity level (CRITICAL, IMPORTANT, MODERATE, LOW).
* **Pending Reboot Tracking:** Active monitoring of kernels and libraries requiring service or system restart (`needs-restarting`, `/var/run/reboot-required`).
* **Batch Operations:** Concurrent execution of upgrade jobs and bulk node decommissioning for decommissioned instances.
* **Native Security Hardening:** Deep systemd sandboxing (`ProtectSystem=strict`, isolation profiles), token-based API authentication, and HMAC-SHA256 / JWT session management.
* **Multi-Distribution Compatibility:** Unified operations across RPM-based (`dnf`, `yum`) and DEB-based (`apt`) Linux distributions.

## 💻 System Requirements

### Recommended Hardware
| Component | Managed Nodes (< 100) | Managed Nodes (100 - 1000+) |
| :--- | :--- | :--- |
| **CPU** | 1 vCPU / Core | 2 - 4 vCPUs |
| **RAM** | 1 GB RAM | 2 - 4 GB RAM |
| **Storage** | 10 GB SSD (`/var/lib` space) | 20+ GB SSD |

### Base Software
* **Operating System:** RHEL 8/9, Rocky Linux, AlmaLinux, CentOS Stream, Debian 11/12, or Ubuntu 20.04/22.04 LTS.
* **Python:** Python 3.8 or higher including `python3-pip` and `python3-venv`.
* **System Utilities:** `curl`, `tar`, `openssl`, `systemd`.
* **Optional (Recommended):** Reverse proxy for TLS termination (`nginx`, `httpd`, or `caddy`).

## 📁 Project Structure & FHS

The server strictly follows the Linux **Filesystem Hierarchy Standard (FHS)**:

* `/opt/orbit-server`: Source tree, helper scripts, and virtual environment (`venv`). Owned by `root:orbit` (least-privilege read/execute).
* `/var/lib/orbit-server`: Persistent operational data and node telemetry (`nodes/`, `tasks/`, `users.json`).
* `/var/log/orbit`: Service activity and error logs (`orbit-server.log`).
* `/etc/sysconfig/orbit-server`: Environment parameters and runtime systemd secrets.

## 🚀 Installation Procedure

### Option A: Quick Bootstrap Installer (Recommended)

The official bootstrap script downloads the latest release (or an explicit tag), prepares system prerequisites, and registers the service unit automatically:

```bash
# Install the latest stable release:
curl -sSL https://raw.githubusercontent.com/ramonromancastro/orbit-server/main/get-orbit.sh | sudo bash

# Or install a specific tagged version with nominal arguments:
curl -sSL https://raw.githubusercontent.com/ramonromancastro/orbit-server/main/get-orbit.sh | sudo bash -s -- --version v1.2.3
```

### Option B: Manual Git Clone

To audit the source and provision the system manually:

```bash
# 1. Clone repository to the FHS deployment directory
sudo git clone [https://github.com/ramonromancastro/orbit-server.git](https://github.com/ramonromancastro/orbit-server.git) /opt/orbit-server

# 2. Enter project path
cd /opt/orbit-server

# 3. Grant execution permissions and run production provisioner
sudo chmod 0770 install.sh
sudo ./install.sh
```

The `install.sh` script automates:

1. Creation of the dedicated `orbit` system group and service user.
2. Creation of required paths under `/opt`, `/var/lib`, and `/var/log`.
3. Initialization of the Python virtual environment and `requirements.txt` resolution.
4. Application of hardened file system permissions based on least privilege.
5. Ingestion of firewall rules via `firewalld` opening the target port if active.
6. Deployment and activation of the `orbit-server.service` systemd unit.

To start the service daemon:

```bash
sudo systemctl start orbit-server
sudo systemctl status orbit-server
```

## ⚙️ System Configuration

### Environment Variables (`/etc/sysconfig/orbit-server`)

This file contains runtime secrets and low-level parameters loaded by systemd. Recommended file permissions: `0600`.

| Variable | Default | Description |
| --- | --- | --- |
| `ORBIT_HOST` | `127.0.0.1` | Network interface address for ASGI listener. Use `0.0.0.0` to listen on all interfaces. |
| `ORBIT_PORT` | `8000` | Inbound TCP listener port. |
| `ORBIT_ROOT_PATH` | *(empty)* | Subdirectory or context prefix when proxied under a path (e.g., `/orbit`). |
| `ORBIT_WORKERS` | `CPUs + 1` | Count of concurrent Uvicorn worker processes handled by Gunicorn. |
| `ORBIT_API_TOKEN` | *Autogenerated* | Master Bearer authentication token required by fleet agents for REST communications. |
| `ORBIT_JWT_SECRET` | *Autogenerated* | Cryptographic signing secret used for dashboard user sessions. |
| `ORBIT_MAX_GLOBAL_RESULTS` | `30` | Maximum historical executions returned in the global audit dashboard view. |
| `ORBIT_MAX_SECURITY_EVENTS` | `200` | Maximum entry count persisted in the security audit log. |
| `ORBIT_RESULTS_RETENTION_DAYS` | `30` | Maximum age in days for agent execution outputs before automatic pruning (`0` to disable). |
| `ORBIT_OFFLINE_THRESHOLD_DAYS` | `30` | Inactivity window in days after which an uncontacted node is marked as *Offline*. |

## 🔑 Initial Credentials

The automated installer seeds a default administrative account:

* **Username:** `admin`
* **Password:** `orbitadmin`

> ⚠️ **Important:** After first sign-in at `http://<SERVER_IP>:8000`, immediately navigate to the **Users Management** panel to rotate the initial administrative password.

## 🛡️ Reverse Proxy (Nginx / Apache)

For production deployments, placing Orbit Server behind a TLS-terminating reverse proxy is strongly recommended.

### Option 1: Root Domain Deployment (`/`)

For setups where Orbit runs at the apex or dedicated subdomain level (e.g., `https://orbit.company.local`).

#### Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name orbit.company.local;

    ssl_certificate /etc/ssl/certs/orbit.crt;
    ssl_certificate_key /etc/ssl/certs/orbit.key;

    location / {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### Apache Configuration

```apache
<VirtualHost *:443>
    ServerName orbit.company.local

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/orbit.crt
    SSLCertificateKeyFile /etc/ssl/certs/orbit.key

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8000/
    ProxyPassReverse / http://127.0.0.1:8000/

    RequestHeader set X-Forwarded-Proto "https"
</VirtualHost>
```

### Option 2: Subdirectory / Context Deployment (e.g., `/orbit-server`)

If Orbit Server must share an existing domain under a dedicated path prefix (e.g., `https://services.company.local/orbit-server`):

#### 1. Set the `ORBIT_ROOT_PATH` Variable

Modify `/etc/sysconfig/orbit-server` to declare the application context prefix:

```bash
# Define target subpath context (do not include trailing slash)
ORBIT_ROOT_PATH=/orbit-server
```

Restart the service unit:

```bash
sudo systemctl restart orbit-server
```

#### 2. Configure Reverse Proxy Upstream Rules

##### Nginx

Include the `X-Forwarded-Prefix` header and omit the trailing slash in `proxy_pass` to allow FastAPI internal path resolution to handle static assets and endpoints transparently:

```nginx
server {
    listen 443 ssl http2;
    server_name services.company.local;

    ssl_certificate /etc/ssl/certs/services.crt;
    ssl_certificate_key /etc/ssl/certs/services.key;

    # Redirect naked directory requests to canonical trailing slash
    location = /orbit-server {
        return 301 /orbit-server/;
    }

    location /orbit-server/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Prefix /orbit-server;
    }
}
```

##### Apache

Ensure `mod_proxy`, `mod_proxy_http`, and `mod_headers` are enabled. Define the `X-Forwarded-Prefix` header:

```apache
<VirtualHost *:443>
    ServerName services.company.local

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/services.crt
    SSLCertificateKeyFile /etc/ssl/certs/services.key

    # Forward context path and scheme indicators
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Prefix "/orbit-server"

    ProxyPreserveHost On
    ProxyPass /orbit-server/ http://127.0.0.1:8000/
    ProxyPassReverse /orbit-server/ http://127.0.0.1:8000/
</VirtualHost>
```

## 📄 License

This software is released under the terms of the **GNU Affero General Public License v3 (AGPLv3)**. Refer to the [LICENSE](https://www.google.com/search?q=LICENSE) file for full legal terms.

## 🤖 Acknowledgments & Development Note

This project was developed with the assistance of Artificial Intelligence (AI) tools, which provided support in code scaffolding, architectural design, documentation, and operational hardening. All source code, security configurations, and deployment logic have been reviewed, tested, and validated for production environments.
