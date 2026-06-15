# AD Inventory Docker

Web inventory for Active Directory computers, virtual machines, printers, network devices, and optional hardware details.

The project runs in Docker Compose and includes:

- FastAPI web UI for viewing and editing inventory records.
- PostgreSQL database.
- Nginx HTTPS reverse proxy.
- AD sync service for physical PCs and virtual machines.
- Printer discovery by SNMP, HTTP, TCP ports, reverse DNS, and optional CSV.
- Network device discovery for switches, access points, routers, storage, and servers.
- Hardware collector over WinRM/CIM for CPU, RAM, disks, GPU, motherboard, monitors, and network adapters.
- Excel import/export for manual fields.

No secrets are committed. Copy `.env.example` to `.env` and fill your own values.

## Repository Layout

```text
app/                  FastAPI application and sync/collector services
scripts/              One-shot maintenance and debug commands
nginx/conf.d/         Nginx reverse proxy config
nginx/certs/          Put HTTPS certificate/key here, ignored by git
certs/ad/             Put AD CA certificate here, ignored by git
exports/              Generated Excel export files, ignored by git
imports/              Optional Excel import files, ignored by git
printers/             Optional local printer CSV, ignored by git
docker-compose.yml    Full stack
Dockerfile            Python application image
.env.example          Safe configuration template
```

## Quick Start

1. Create a local configuration file:

```bash
cp .env.example .env
```

2. Edit `.env` and at minimum set:

```env
INVENTORY_HOST=inventory.example.local
APP_PASSWORD=change_this_web_password
POSTGRES_PASSWORD=change_this_db_password
AD_SERVER=ldaps://dc01.example.local:636
AD_USER=EXAMPLE\\inventory.reader
AD_PASSWORD=change_this_ad_password
AD_USER_BASE_DN=DC=example,DC=local
AD_COMPUTER_PHYSICAL_BASE_DN=OU=Workstations,DC=example,DC=local
AD_COMPUTER_VIRTUAL_BASE_DN=OU=Virtual Workstations,OU=Workstations,DC=example,DC=local
```

3. Add DNS record in your internal DNS:

```text
inventory.example.local -> Docker host IP
```

4. Put HTTPS certificate and key into:

```text
nginx/certs/inventory.example.local.crt
nginx/certs/inventory.example.local.key
```

5. Start:

```bash
docker compose up -d --build
```

6. Open:

```text
https://inventory.example.local/
```

## Configuration

### Web Login

```env
APP_USER=admin
APP_PASSWORD=change_this_web_password
```

The web UI uses HTTP Basic auth.

### PostgreSQL

```env
POSTGRES_DB=inventory
POSTGRES_USER=inventory
POSTGRES_PASSWORD=change_this_db_password
```

The database is created by the official PostgreSQL container on first start.

### Active Directory

Use a read-only domain account:

```env
AD_SERVER=ldaps://dc01.example.local:636
AD_USER=EXAMPLE\\inventory.reader
AD_PASSWORD=change_this_ad_password
AD_USE_SSL=true
AD_REQUIRE_LDAPS=true
AD_VALIDATE_CERT=false
AD_CA_CERT_FILE=/certs/ad/ad-ca.crt
```

For certificate validation, place your internal CA certificate at:

```text
certs/ad/ad-ca.crt
```

Then set:

```env
AD_VALIDATE_CERT=true
```

### AD Search Bases

```env
AD_USER_BASE_DN=DC=example,DC=local
AD_COMPUTER_PHYSICAL_BASE_DN=OU=Workstations,DC=example,DC=local
AD_COMPUTER_VIRTUAL_BASE_DN=OU=Virtual Workstations,OU=Workstations,DC=example,DC=local
AD_PHYSICAL_SEARCH_SCOPE=LEVEL
AD_VIRTUAL_SEARCH_SCOPE=SUBTREE
```

Physical and virtual machines can be stored in different OUs. Records removed from these OUs can be deleted from inventory when:

```env
DELETE_MISSING_COMPUTERS=true
```

### User Matching

The sync service matches computer names to AD users by normalized name tokens.

Examples:

```text
JOHN-SMITH        -> john.smith
VM-JOHN-SMITH     -> john.smith
OLD-JOHN-SMITH    -> john.smith
```

For matched users, the service reads display name and organization fields such as title, department, and company.

### Manual Fields

The following fields are safe from AD sync overwrite:

- MAC
- socket
- inventory number
- switch/port
- location
- note
- manually edited hardware fields

AD/DNS sync may update:

- hostname
- matched user
- title
- department/company
- works-on type
- IP address
- match status
- access flag if configured by AD groups

### Access Flag From AD Groups

Optional computer groups can automatically fill the access flag:

```env
VPN_GROUP_DN=CN=VPN_Access,OU=Groups,DC=example,DC=local
FIREWALL_GROUP_DN=CN=Firewall_Access,OU=Groups,DC=example,DC=local
```

Computers in the VPN group get `Да`; computers in the Firewall group get `Нет`.

### Laptop Detection By WiFi Networks

Set CIDR ranges or start-end ranges:

```env
WIFI_NETWORKS=192.0.2.0/28,198.51.100.10-20
```

If a physical or virtual machine has an IP inside these ranges, `works_on` is shown as `Ноутбук`.

## Printer Discovery

Enable SNMP/HTTP/TCP discovery and set only networks you are allowed to scan:

```env
PRINTER_SNMP_DISCOVERY_ENABLED=true
PRINTER_SNMP_SUBNETS=192.0.2.0/28
PRINTER_SNMP_COMMUNITY=public
```

The service tries:

- SNMP model/name/location.
- HTTP title and common printer status pages.
- TCP port probes for known printer services.
- Reverse DNS.
- Optional local CSV.

Optional CSV file:

```text
printers/printers.csv
```

Format:

```csv
name,ip,location,note
Example Printer,192.0.2.10,Office 1,Manual entry
```

## Network Device Discovery

Enable discovery for switches, access points, routers, storage, servers, and other network devices:

```env
NETWORK_DEVICE_DISCOVERY_ENABLED=true
NETWORK_DEVICE_SUBNETS=198.51.100.0/28,203.0.113.10-20
```

Supported target formats:

```text
192.0.2.0/24
198.51.100.10-20
203.0.113.15
```

Discovery uses SNMP, HTTP titles, TLS certificate names, TCP ports, and reverse DNS. Unknown devices can be skipped with:

```env
NETWORK_DEVICE_INCLUDE_UNNAMED=false
```

## Hardware Collection

Hardware collection is optional and disabled by default in `.env.example`.

```env
HARDWARE_COLLECTOR_ENABLED=true
HARDWARE_WINRM_USER=EXAMPLE\\inventory.hardware
HARDWARE_WINRM_PASSWORD=change_this_winrm_password
HARDWARE_WINRM_SCHEME=http
HARDWARE_WINRM_PORT=5985
HARDWARE_COLLECTION_MODE=wmic
```

Requirements:

- WinRM must be enabled on target machines.
- Docker host must reach `5985/tcp` or `5986/tcp`.
- The hardware account needs rights to read CIM/WMI remotely.
- Domain Users alone is usually not enough.

Recommended Windows-side permissions:

- Add a domain group for inventory hardware readers.
- Add that group to local Administrators, or grant Remote Management Users plus WMI namespace permissions.
- Allow Windows Remote Management through host firewall.

Collected fields:

- CPU
- RAM total, slots used/free, module model/frequency
- disks
- GPU
- motherboard
- monitors
- network adapters, link status, speed, MAC

Monitor collection uses active WMI data first. If that fails on newer Windows where `wmic.exe` is absent, the collector can fall back to registry EDID data and limit the result:

```env
HARDWARE_MAX_MONITORS=2
```

Debug a host:

```bash
docker compose exec hardware python -m scripts.debug_hardware_host pc01.example.local --monitor-sources
```

## Excel Import And Export

The application can export an Excel file to:

```env
EXPORT_PATH=/exports/inventory.xlsx
```

Open import page:

```text
https://inventory.example.local/import
```

The import feature is useful for migrating old manually maintained spreadsheets into PostgreSQL.

## One-Shot Commands

Run AD sync only:

```bash
docker compose exec sync python -m scripts.run_ad_sync
```

Debug hardware host:

```bash
docker compose exec hardware python -m scripts.debug_hardware_host pc01.example.local --monitor-sources
```

View logs:

```bash
docker compose logs -f web
docker compose logs -f sync
docker compose logs -f hardware
```

## HTTPS Certificates

Nginx expects:

```text
nginx/certs/inventory.example.local.crt
nginx/certs/inventory.example.local.key
```

For production, use a certificate trusted by your internal clients. If certificates are renewed outside this project, copy the refreshed files into `nginx/certs/`. Nginx reloads periodically using `NGINX_RELOAD_INTERVAL_SECONDS`.

Run:

```bash
rg -n "PASSWORD|TOKEN|SECRET|PRIVATE KEY|example.local|192.0.2.|198.51.100.|203.0.113." .
```

The `example.local`, `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` values are documentation placeholders.


