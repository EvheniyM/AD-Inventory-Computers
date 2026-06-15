from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_user: str = "admin"
    app_password: str = "change_me"
    app_timezone: str = "Europe/Kiev"
    hardware_report_token: str = ""

    database_url: str = "postgresql+psycopg://inventory:change_this_db_password@db:5432/inventory"

    ad_server: str = ""
    ad_user: str = ""
    ad_password: str = ""
    ad_use_ssl: bool = True
    ad_require_ldaps: bool = True
    ad_validate_cert: bool = False
    ad_ca_cert_file: str = ""
    ad_allow_insecure_tls: bool = False
    ad_user_base_dn: str = "DC=example,DC=local"
    ad_computer_physical_base_dn: str = "OU=Workstations,DC=example,DC=local"
    ad_computer_virtual_base_dn: str = "OU=Virtual Workstations,OU=Workstations,DC=example,DC=local"
    ad_physical_search_scope: str = Field(default="LEVEL", pattern="^(LEVEL|SUBTREE)$")
    ad_virtual_search_scope: str = Field(default="SUBTREE", pattern="^(LEVEL|SUBTREE)$")
    checkpoint_vpn_group_dn: str = (
        "CN=VPN_Access,OU=Groups,DC=example,DC=local"
    )
    checkpoint_firewall_group_dn: str = (
        "CN=Firewall_Access,OU=Groups,DC=example,DC=local"
    )

    sync_interval_seconds: int = 300
    delete_missing_computers: bool = True
    write_export_on_change: bool = True
    export_path: str = "/exports/inventory.xlsx"
    printers_file: str = "/printers/printers.csv"
    printer_clear_before_sync: bool = True
    printers_delete_missing: bool = True
    printer_snmp_discovery_enabled: bool = True
    printer_snmp_subnets: str = ""
    printer_snmp_community: str = "public"
    printer_snmp_port: int = 161
    printer_snmp_timeout_seconds: float = 1.0
    printer_snmp_workers: int = 64
    printer_snmp_max_hosts: int = 4096
    printer_snmp_require_keywords: bool = False
    printer_http_discovery_enabled: bool = True
    printer_http_require_keywords: bool = True
    printer_http_name_enabled: bool = True
    printer_http_name_ports: str = "80,443,8080,8000,8443,631"
    printer_http_name_paths: str = (
        "/,/index.html,/index.htm,/home.html,/status.html,/start.htm,/main.html,"
        "/device_status.html,/general/status.html,/web/guest/en/websys/webArch/mainFrame.cgi"
    )
    printer_http_name_timeout_seconds: float = 1.5
    printer_tcp_discovery_enabled: bool = True
    printer_tcp_ports: str = "9100,515,631"
    printer_tcp_timeout_seconds: float = 0.7
    printer_reverse_dns_enabled: bool = True
    printer_snmp_include_keywords: str = (
        "printer,mfp,mfu,canon,hp,hewlett,packard,kyocera,xerox,epson,brother,"
        "ricoh,sharp,lexmark,konica,minolta,samsung,laserjet,officejet,deskjet,imageclass,"
        "workcentre,versalink,phaser,docucentre"
    )
    printer_snmp_exclude_keywords: str = "switch,router,firewall,vmware,esxi,linux,windows,ups,nas"

    network_device_discovery_enabled: bool = True
    network_device_subnets: str = ""
    network_device_clear_before_sync: bool = False
    network_device_delete_missing: bool = True
    network_device_snmp_community: str = "public"
    network_device_snmp_port: int = 161
    network_device_snmp_timeout_seconds: float = 1.0
    network_device_workers: int = 64
    network_device_max_hosts: int = 4096
    network_device_http_enabled: bool = True
    network_device_http_ports: str = "80,443,8080,8000,8443"
    network_device_http_timeout_seconds: float = 1.5
    network_device_tls_name_enabled: bool = True
    network_device_tls_ports: str = "443,8443"
    network_device_tls_timeout_seconds: float = 1.5
    network_device_tcp_discovery_enabled: bool = True
    network_device_tcp_ports: str = "22,23,80,443,445,3389,5985,5986,8080,8443"
    network_device_tcp_timeout_seconds: float = 0.7
    network_device_reverse_dns_enabled: bool = True
    network_device_include_unnamed: bool = False
    network_device_exclude_keywords: str = (
        "printer,mfp,mfu,canon,laserjet,officejet,deskjet,workcentre,phaser,pixma,imageclass"
    )
    dns_resolve_ip: bool = True
    dns_query_timeout_seconds: float = 1.5
    dns_resolve_workers: int = 24
    wifi_networks: str = ""

    hardware_collector_enabled: bool = False
    hardware_collect_network_servers: bool = True
    hardware_collect_memory_details: bool = True
    hardware_collect_monitors: bool = True
    hardware_collect_network_adapters: bool = True
    hardware_max_monitors: int = 2
    hardware_clear_before_collection: bool = False
    hardware_collection_interval_seconds: int = 21600
    hardware_collect_workers: int = 8
    hardware_collection_mode: str = Field(default="wmic", pattern="^(wmic|powershell)$")
    hardware_winrm_user: str = ""
    hardware_winrm_password: str = ""
    hardware_winrm_scheme: str = Field(default="http", pattern="^(http|https)$")
    hardware_winrm_port: int = 5985
    hardware_winrm_transport: str = "ntlm"
    hardware_winrm_server_cert_validation: str = Field(default="ignore", pattern="^(ignore|validate)$")
    hardware_winrm_precheck_enabled: bool = True
    hardware_winrm_precheck_timeout_seconds: float = 3.0
    hardware_winrm_operation_timeout_seconds: int = 20
    hardware_winrm_read_timeout_seconds: int = 30


@lru_cache
def get_settings() -> Settings:
    return Settings()
