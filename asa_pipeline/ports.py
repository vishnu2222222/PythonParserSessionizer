from __future__ import annotations

SERVICE_HINTS: dict[int, str] = {
    22: "ssh",
    23: "telnet",
    53: "dns",
    80: "http",
    88: "kerberos",
    135: "rpc",
    137: "netbios",
    138: "netbios",
    139: "netbios",
    389: "ldap",
    443: "https",
    445: "smb",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5985: "winrm",
    5986: "winrm",
    8080: "web_alt",
    8443: "web_alt",
}


def infer_service_hint(port: int | None) -> str | None:
    if port is None:
        return None
    return SERVICE_HINTS.get(port)
