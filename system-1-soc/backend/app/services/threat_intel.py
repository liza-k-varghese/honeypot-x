"""
Threat intelligence — Group 5 (IP Intelligence, GeoIP, ASN, ISP,
Reputation, Tor/VPN/Proxy indicators, Enrichment).

Every lookup degrades gracefully when its data source isn't configured
(no GeoLite2 database downloaded yet, no AbuseIPDB key set) rather than
raising — enrichment is a "nice to have" layer on top of detection, and
a missing API key should never block an attack from being logged and
alerted on.
"""

import ipaddress
import os
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    requests = None

from app.core.config import settings

_geoip_reader = None
_tor_exit_nodes: set[str] | None = None


def _get_geoip_reader():
    global _geoip_reader
    if _geoip_reader is None and os.path.exists(settings.GEOIP_DB_PATH):
        import geoip2.database
        _geoip_reader = geoip2.database.Reader(settings.GEOIP_DB_PATH)
    return _geoip_reader


def lookup_geoip(ip_address: str) -> dict:
    """Country/city/lat/lon from a local MaxMind GeoLite2-City database.
    Download it yourself (free MaxMind account required) and point
    GEOIP_DB_PATH at it — not bundled here since it's a licensed,
    regularly-updated binary file, not something to vendor into a repo."""
    reader = _get_geoip_reader()
    if reader is None:
        return {"country": None, "city": None, "latitude": None, "longitude": None}
    try:
        response = reader.city(ip_address)
        return {
            "country": response.country.name,
            "city": response.city.name,
            "latitude": response.location.latitude,
            "longitude": response.location.longitude,
        }
    except Exception:
        return {"country": None, "city": None, "latitude": None, "longitude": None}


def lookup_asn(ip_address: str) -> dict:
    """ASN + organization from a local GeoLite2-ASN database, if present
    alongside the City database (same MaxMind account, separate file)."""
    asn_db_path = settings.GEOIP_DB_PATH.replace("GeoLite2-City", "GeoLite2-ASN")
    if not os.path.exists(asn_db_path):
        return {"asn": None, "isp": None, "organization": None}
    try:
        import geoip2.database
        with geoip2.database.Reader(asn_db_path) as reader:
            response = reader.asn(ip_address)
            return {
                "asn": response.autonomous_system_number,
                "isp": response.autonomous_system_organization,
                "organization": response.autonomous_system_organization,
            }
    except Exception:
        return {"asn": None, "isp": None, "organization": None}


def lookup_reputation(ip_address: str) -> dict:
    """Queries AbuseIPDB if ABUSEIPDB_API_KEY is set. Returns a 0-100
    abuse confidence score (higher = worse). Without a key, returns None
    rather than a fabricated score — an absent reputation is meaningfully
    different from a confirmed-clean one, and the two should never be
    conflated in the dashboard."""
    if not settings.ABUSEIPDB_API_KEY or requests is None:
        return {"reputation_score": None, "reputation_source": None}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip_address, "maxAgeInDays": 90},
            headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "reputation_score": data.get("abuseConfidenceScore"),
            "reputation_source": "AbuseIPDB",
        }
    except requests.RequestException:
        return {"reputation_score": None, "reputation_source": None}


def _load_tor_exit_nodes() -> set[str]:
    global _tor_exit_nodes
    if _tor_exit_nodes is not None:
        return _tor_exit_nodes
    _tor_exit_nodes = set()
    if os.path.exists(settings.TOR_EXIT_LIST_PATH):
        with open(settings.TOR_EXIT_LIST_PATH) as f:
            _tor_exit_nodes = {line.strip() for line in f if line.strip() and not line.startswith("#")}
    return _tor_exit_nodes


def is_tor_exit_node(ip_address: str) -> bool:
    """Checks against a locally cached exit-node list (refresh it
    periodically from https://check.torproject.org/torbulkexitlist via a
    cron job — not fetched live per-request to avoid a network round trip
    on every single lookup)."""
    return ip_address in _load_tor_exit_nodes()


# Heuristic only — real VPN/proxy detection needs a paid feed (IPQualityScore,
# etc.). This keyword match against ASN organization names catches a
# meaningful fraction of commercial VPN/hosting providers for a project of
# this scope, but false negatives are expected and should be documented as
# a known limitation in the report, not presented as authoritative.
_VPN_HOSTING_KEYWORDS = [
    "vpn", "hosting", "cloud", "digitalocean", "ovh", "hetzner",
    "linode", "vultr", "amazon", "google cloud", "microsoft azure",
]


def guess_vpn_or_proxy(organization: str | None) -> dict:
    if not organization:
        return {"is_vpn_indicator": False, "is_proxy_indicator": False}
    org_lower = organization.lower()
    is_vpn = any(kw in org_lower for kw in _VPN_HOSTING_KEYWORDS)
    return {"is_vpn_indicator": is_vpn, "is_proxy_indicator": is_vpn}


def is_private_ip(ip_address: str) -> bool:
    """True for RFC1918 LAN ranges (10/8, 172.16/12, 192.168/16) and also
    loopback, link-local, and RFC5737 documentation ranges (203.0.113.0/24,
    198.51.100.0/24, 192.0.2.0/24) — Python's stdlib groups all of these
    under `is_private` since none of them are real internet-routable
    addresses, so none of them will ever have genuine GeoIP/ASN/reputation
    data to enrich.

    Worth knowing: the demo Cowrie traffic generated in the companion
    smart-firewall-honeypot project (scripts/generate_sample_log.py) uses
    203.0.113.x / 198.51.100.x as stand-in "attacker" IPs, per the common
    documentation convention — those will short-circuit here too. If you
    reuse that same demo-data pattern to test HoneyShield X's enrichment
    pipeline, swap in real-looking public IPs (or your own public IP) to
    actually see GeoIP/ASN/reputation fields populate; RFC5737 IPs will
    always come back with everything null, by design, not by bug."""
    try:
        return ipaddress.ip_address(ip_address).is_private
    except ValueError:
        return False


def enrich(ip_address: str) -> dict:
    """The single entry point the ingestion worker calls per new attacker
    IP. Combines every lookup above into one ThreatIntelligence-shaped
    dict — see app/models.py for the destination table."""
    if is_private_ip(ip_address):
        # Don't waste API calls / GeoIP lookups on internal/whitelisted
        # traffic — it was never going to have meaningful geo/ASN data.
        return {
            "ip_address": ip_address, "country": None, "city": None,
            "latitude": None, "longitude": None, "asn": None, "isp": None,
            "organization": None, "is_tor_exit_node": False,
            "is_vpn_indicator": False, "is_proxy_indicator": False,
            "reputation_score": None, "reputation_source": None,
            "last_enriched_at": datetime.now(timezone.utc),
        }

    geo = lookup_geoip(ip_address)
    asn_info = lookup_asn(ip_address)
    reputation = lookup_reputation(ip_address)
    vpn_proxy = guess_vpn_or_proxy(asn_info.get("organization"))

    return {
        "ip_address": ip_address,
        **geo,
        **asn_info,
        "is_tor_exit_node": is_tor_exit_node(ip_address),
        **vpn_proxy,
        **reputation,
        "last_enriched_at": datetime.now(timezone.utc),
    }


