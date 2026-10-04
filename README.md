A continuación se presenta la documentación técnica oficial y actualizada para el despliegue de **Orbit Enterprise Server**. Esta guía abarca todas las políticas de retención, configuraciones de contexto (Proxy) y ajustes de seguridad implementados recientemente.

---

# 🚀 Guía de Instalación: Orbit Enterprise Server

Orbit Enterprise es un orquestador centralizado diseñado para la gestión automatizada de parches y auditoría de flotas Linux. Soporta despliegues tradicionales (Bare-metal/Systemd) y entornos contenerizados (Docker).

## Requisitos Previos Generales

* **Sistema Operativo:** Linux (Debian/Ubuntu, RHEL/CentOS/Rocky).
* **Dependencias (Tradicional):** Python 3.8+, `pip`, `venv`, Apache/Nginx.
* **Dependencias (Docker):** Docker Engine 20.10+, Docker Compose v2.
* **Red:** Puerto 80/443 expuesto para los agentes y administradores.

---

## 🛠️ Método A: Instalación Tradicional (Bare-Metal / Systemd)

Este método es ideal para infraestructuras clásicas donde se requiere control absoluto a nivel de sistema operativo y gestión nativa de logs.

### 1. Preparación del Entorno

Cree un usuario de sistema dedicado y prepare los directorios base:

```bash
useradd -r -s /bin/false orbit
mkdir -p /opt/orbit-server/orbit_data/{nodes,tasks}
mkdir -p /var/log/orbit
chown -R orbit:orbit /opt/orbit-server /var/log/orbit
chmod 755 /var/log/orbit

```

Copie los archivos del servidor (`main.py`, carpeta `web/`, etc.) dentro de `/opt/orbit-server/` y configure el entorno virtual:

```bash
cd /opt/orbit-server
chown -R orbit:orbit /opt/orbit-server
sudo -u orbit wget -O /opt/orbit-server/web/assets/js/charts.js/chart.umd.min.js https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js
sudo -u orbit python3 -m venv venv
sudo -u orbit ./venv/bin/pip install -r requirements.txt
```

### 2. Archivo de Configuración Central

Cree el archivo de variables de entorno del sistema (`/etc/sysconfig/orbit-server` en RHEL o `/etc/default/orbit-server` en Debian):

```ini
# ==========================================
# ORBIT ENTERPRISE SERVER CONFIGURATION
# ==========================================

# --- NETWORKING ---
# Interfaz de escucha (127.0.0.1 recomendado si está detrás de Apache/Nginx)
ORBIT_HOST=127.0.0.1

# Puerto de escucha de Uvicorn
ORBIT_PORT=8000

# Contexto o subdirectorio para el proxy inverso.
# Dejar en blanco o comentar si se sirve directamente en la raíz (/)
ORBIT_ROOT_PATH=/orbit-server

# --- SECURITY ---
# Token maestro para la API y autenticación de agentes
ORBIT_API_TOKEN=SuTokenSuperSeguro123
# Secret de sesión
ORBIT_JWT_SECRET=SuJwtSecretSuperSeguro123

# --- DASHBOARD & RETENTION POLICIES ---
# Número máximo de filas a mostrar en el 'Global Execution Audit Log' del panel web
ORBIT_MAX_GLOBAL_RESULTS=30

# Límite máximo de registros a conservar en el archivo security_events.json
ORBIT_MAX_SECURITY_EVENTS=200

# Días de retención histórica para los resultados de tareas de los agentes (*_*_result.json)
# (0 para desactivar el borrado automático)
ORBIT_RESULTS_RETENTION_DAYS=30

# Días sin comunicación tras los cuales un servidor se considera 'Offline'
ORBIT_OFFLINE_THRESHOLD_DAYS=30
```

Proteja el archivo: `sudo chmod 600 /etc/sysconfig/orbit-server`

### 3. Servicio Systemd

Cree el archivo de servicio `/etc/systemd/system/orbit-server.service`:

```ini
[Unit]
Description=Orbit Enterprise Server (FastAPI)
After=network.target

[Service]
User=orbit
Group=orbit
WorkingDirectory=/opt/orbit-server

EnvironmentFile=-/etc/default/orbit-server
EnvironmentFile=-/etc/sysconfig/orbit-server

# Gunicorn gestionando múltiples procesos de Uvicorn
ExecStart=/opt/orbit-server/venv/bin/gunicorn main:app \
  --workers <(CPU CORES x 2) + 1> \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind ${ORBIT_HOST}:${ORBIT_PORT} \
  --access-logfile - \
  --error-logfile -

# Redirección de logs
StandardOutput=append:/var/log/orbit/orbit-server.log
StandardError=append:/var/log/orbit/orbit-error.log
Restart=always

[Install]
WantedBy=multi-user.target
```

Habilite y arranque el servicio:

```bash
systemctl daemon-reload
systemctl enable --now orbit-server

```

### 4. Proxy Inverso (Apache)

Configure Apache para interceptar el tráfico TLS y enviarlo al orquestador bajo el contexto especificado:

```apache
<VirtualHost _default_:443>
    # (Configuraciones previas de SSLEngine, Certificados, etc.)

    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader set X-Forwarded-Prefix "/orbit-server"

    ProxyPreserveHost On
    ProxyPass /orbit-server/ http://127.0.0.1:8000/
    ProxyPassReverse /orbit-server/ http://127.0.0.1:8000/
</VirtualHost>

```

### 5. Rotación de Logs

Cree `/etc/logrotate.d/orbit-server` para evitar la saturación del disco:

```text
/var/log/orbit/*.log {
    daily
    rotate 14
    missingok
    compress
    delaycompress
    notifempty
    copytruncate
    create 0640 orbit orbit
}

```

---

## 🐳 Método B: Instalación por Contenedores (Docker)

Ideal para infraestructuras modernas, garantizando inmutabilidad y despliegues ultrarrápidos.

### 1. Dockerfile

En la raíz de su proyecto (`/opt/orbit-server`), cree el siguiente `Dockerfile`:

```dockerfile
FROM python:3.11-slim

# Crear usuario no root
RUN useradd -m -r orbit_user
WORKDIR /app

# Instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar aplicativo
COPY . /app
RUN mkdir -p /app/nodes /app/tasks && chown -R orbit_user:orbit_user /app

USER orbit_user
EXPOSE 8000

# El host es 0.0.0.0 en Docker para exponer el puerto al exterior del contenedor
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

```

### 2. Archivo `docker-compose.yml`

Cree el archivo de orquestación que incluirá todas nuestras variables dinámicas y persistirá los datos:

```yaml
version: '3.8'

services:
  orbit-server:
    build: .
    container_name: orbit_enterprise
    restart: unless-stopped
    ports:
      - "127.0.0.1:8000:8000" # Expuesto solo a localhost para el proxy inverso
    environment:
      - ORBIT_API_TOKEN=SuTokenSuperSeguro123
      - ORBIT_ROOT_PATH=/orbit-server
      - ORBIT_MAX_GLOBAL_RESULTS=30
      - ORBIT_MAX_SECURITY_EVENTS=200
      - ORBIT_RESULTS_RETENTION_DAYS=30
      - ORBIT_OFFLINE_THRESHOLD_DAYS=30
    volumes:
      - orbit_nodes:/app/nodes
      - orbit_tasks:/app/tasks
      - orbit_security:/app/security_events.json

volumes:
  orbit_nodes:
  orbit_tasks:
  orbit_security:

```

### 3. Ejecución

Despliegue el contenedor en segundo plano:

```bash
docker-compose up -d

```

*(Nota: Incluso utilizando Docker, necesitará un proxy inverso como Apache o Nginx en el host o en otro contenedor para gestionar el certificado SSL y la terminación HTTPS apuntando al puerto 8000).*