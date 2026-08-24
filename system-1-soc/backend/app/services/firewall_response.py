"""
Automated firewall response — Group 10, Feature 100 (Controlled
Automated Response).

Same design proven out in the companion smart-firewall-honeypot
project's automation/firewall_manager.py, adapted into HoneyShield X's
config system: pfSense REST API, pfSense over SSH, local iptables, or a
mock that just logs — selected by settings.FIREWALL_BACKEND. This is
what actually closes the loop that app.services.alerting's
recommend_response_action() left open: that function only ever
*recommended* blocking; this module is what would actually do it, gated
behind settings.AUTOMATED_RESPONSE_ENABLED so nothing fires until you've
deliberately turned it on.
"""

import logging

from app.core.config import settings

logger = logging.getLogger("firewall_response")

try:
    import requests
except ImportError:
    requests = None

try:
    import paramiko
except ImportError:
    paramiko = None


class FirewallError(Exception):
    pass


class PfSenseFirewall:
    """Adds attacker IPs to a pfSense firewall alias via the REST API
    (jaredhendrickson13/pfsense-api or pfSense 2.7+/Plus's built-in API).
    See the companion project's firewall_manager.py for the fuller
    pfSense setup walkthrough (alias creation, WAN block rule) — the
    mechanics are identical here, just reading config from
    HoneyShield X's own settings object."""

    def __init__(self, host, api_key, alias, verify_tls=False):
        if requests is None:
            raise FirewallError("The 'requests' package is required for the pfsense backend")
        self.host = host.rstrip("/")
        self.api_key = api_key
        self.alias = alias
        self.verify_tls = verify_tls

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def block_ip(self, ip: str, reason: str = ""):
        url = f"{self.host}/api/v2/firewall/alias/entry"
        payload = {"name": self.alias, "address": ip, "detail": reason or "HoneyShield X automated response"}
        resp = requests.post(url, json=payload, headers=self._headers(), verify=self.verify_tls, timeout=10)
        if resp.status_code >= 300:
            raise FirewallError(f"pfSense API error {resp.status_code}: {resp.text}")
        requests.post(f"{self.host}/api/v2/firewall/apply", headers=self._headers(), verify=self.verify_tls, timeout=10)
        logger.info("pfSense: blocked %s via alias %s", ip, self.alias)


class PfSenseSSHFirewall:
    """Alternative to the REST API — connects over SSH and runs
    `pfctl -t <table> -T add <ip>` directly, for pfSense installs without
    the API package. Requires SSH access enabled on pfSense and a pf
    table already referenced by a WAN block rule."""

    def __init__(self, host, username, key_path=None, password=None, pf_table="honeyshield_blacklist", port=22):
        if paramiko is None:
            raise FirewallError("The 'paramiko' package is required for the pfsense_ssh backend")
        if not key_path and not password:
            raise FirewallError("pfsense_ssh backend requires either PFSENSE_SSH_KEY_PATH or PFSENSE_SSH_PASSWORD")
        self.host = host
        self.username = username
        self.key_path = key_path
        self.password = password
        self.pf_table = pf_table
        self.port = port

    def _connect(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if self.key_path:
            client.connect(self.host, port=self.port, username=self.username, key_filename=self.key_path, timeout=10)
        else:
            client.connect(self.host, port=self.port, username=self.username, password=self.password, timeout=10)
        return client

    def block_ip(self, ip: str, reason: str = ""):
        command = f"pfctl -t {self.pf_table} -T add {ip}"
        client = self._connect()
        try:
            stdin, stdout, stderr = client.exec_command(command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                raise FirewallError(f"pfctl error (exit {exit_status}): {stderr.read().decode().strip()}")
            logger.info("pfSense (SSH): blocked %s in table %s", ip, self.pf_table)
        finally:
            client.close()


class IPTablesFirewall:
    """Blocks on the local machine running this backend — useful for the
    dev environment or a single-box deployment. Requires root/CAP_NET_ADMIN."""

    def block_ip(self, ip: str, reason: str = ""):
        import subprocess

        try:
            subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], check=True, capture_output=True)
            logger.info("iptables: %s already blocked", ip)
            return
        except subprocess.CalledProcessError:
            pass

        result = subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, text=True)
        if result.returncode != 0:
            raise FirewallError(f"iptables error: {result.stderr}")
        logger.info("iptables: blocked %s", ip)


class MockFirewall:
    """No-op backend — logs what would happen. This is the default
    (settings.FIREWALL_BACKEND='mock') so a fresh deployment never
    silently blocks real traffic before you've deliberately configured
    and tested a real backend."""

    def block_ip(self, ip: str, reason: str = ""):
        logger.info("[MOCK] would block %s (reason: %s)", ip, reason)


def get_backend():
    backend = settings.FIREWALL_BACKEND
    if backend == "pfsense":
        return PfSenseFirewall(settings.PFSENSE_HOST, settings.PFSENSE_API_KEY, settings.PFSENSE_BLOCKLIST_ALIAS, settings.PFSENSE_VERIFY_TLS)
    if backend == "pfsense_ssh":
        return PfSenseSSHFirewall(
            settings.PFSENSE_SSH_HOST, settings.PFSENSE_SSH_USER,
            key_path=settings.PFSENSE_SSH_KEY_PATH or None, password=settings.PFSENSE_SSH_PASSWORD or None,
            pf_table=settings.PFSENSE_PF_TABLE, port=settings.PFSENSE_SSH_PORT,
        )
    if backend == "iptables":
        return IPTablesFirewall()
    if backend == "mock":
        return MockFirewall()
    raise FirewallError(f"Unknown FIREWALL_BACKEND: {backend}")


def block_ip(ip: str, reason: str = "") -> dict:
    """Single entry point playbooks.py calls. Returns a result dict
    rather than raising on failure — a failed block shouldn't crash the
    ingestion pipeline that triggered it; the caller records success/
    failure either way (see app.services.playbooks.execute_playbook)."""
    if not settings.AUTOMATED_RESPONSE_ENABLED:
        logger.info("Automated response disabled (AUTOMATED_RESPONSE_ENABLED=false) — not blocking %s", ip)
        return {"success": False, "skipped": True, "reason": "automated response disabled"}

    try:
        get_backend().block_ip(ip, reason)
        return {"success": True, "skipped": False, "backend": settings.FIREWALL_BACKEND}
    except FirewallError as exc:
        logger.error("Failed to block %s: %s", ip, exc)
        return {"success": False, "skipped": False, "error": str(exc)}


