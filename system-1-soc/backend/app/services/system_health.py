"""
System Health & Infrastructure Monitoring — Group 15.

Local metrics (CPU/RAM/disk) use psutil directly. Remote service checks
(TCP/HTTP) and Docker container status are best-effort: a check that
can't complete (service down, Docker not reachable, network blip) reports
"unhealthy" rather than raising, since the whole point of a health check
is to survive the thing it's checking being broken.
"""

import socket
import subprocess

import psutil
import requests

from app.core.config import settings


# ---------------------------------------------------------------------------
# Features 141-143: CPU / RAM / Disk monitoring
# ---------------------------------------------------------------------------

def get_local_metrics() -> dict:
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage("/").percent,
    }


# ---------------------------------------------------------------------------
# Feature 144: Network Health Monitoring
# ---------------------------------------------------------------------------

def check_tcp_port(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_http_health(url: str, timeout: float = 5.0) -> bool:
    try:
        resp = requests.get(url, timeout=timeout)
        return resp.status_code < 500
    except requests.RequestException:
        return False


# ---------------------------------------------------------------------------
# Features 145-146, 149: Honeypot / IDS / Container health monitoring
# ---------------------------------------------------------------------------

def check_docker_container(container_name: str) -> bool | None:
    """Returns True/False if Docker is reachable and the container exists,
    or None if Docker itself couldn't be queried (e.g. this process
    doesn't have Docker socket access) — None is deliberately distinct
    from False, so the dashboard can show "unknown" rather than falsely
    claiming a service is down when the real problem is the health check
    itself lacking permissions."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return False
        return result.stdout.strip() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


# ---------------------------------------------------------------------------
# Features 147-148: Database / API health monitoring — thin wrappers
# around check_tcp_port for the specific ports this stack uses.
# ---------------------------------------------------------------------------

def check_postgres_health() -> bool:
    return check_tcp_port(settings.POSTGRES_HOST, settings.POSTGRES_PORT)


def check_redis_health() -> bool:
    return check_tcp_port(settings.REDIS_HOST, settings.REDIS_PORT)


def check_opensearch_health() -> bool:
    scheme = "https" if settings.OPENSEARCH_USE_SSL else "http"
    return check_http_health(f"{scheme}://{settings.OPENSEARCH_HOST}:{settings.OPENSEARCH_PORT}")


# ---------------------------------------------------------------------------
# Feature 150: Service Failure Detection + Feature 162: Storage Threshold
# Alerts — pure decision logic over already-collected metrics/statuses.
# ---------------------------------------------------------------------------

def find_failed_services(services_status: dict[str, bool]) -> list[str]:
    return [name for name, is_up in services_status.items() if not is_up]


def determine_overall_health(services_status: dict[str, bool]) -> bool:
    return len(find_failed_services(services_status)) == 0


def classify_disk_alert(disk_percent: float) -> str | None:
    if disk_percent >= settings.DISK_USAGE_CRITICAL_PERCENT:
        return "critical"
    if disk_percent >= settings.DISK_USAGE_WARNING_PERCENT:
        return "warning"
    return None


