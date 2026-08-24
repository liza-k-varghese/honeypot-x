"""
Log normalization — Group 4 (Log Normalization, Event Timestamping).

Each of the 5 sources Filebeat ships (Cowrie, OpenCanary, Dionaea, Zeek,
Suricata) has a completely different JSON schema. This module is the
single place that turns any of them into one common shape matching
app.models.AttackEvent, so everything downstream (detection, threat
intel, correlation, AI) only ever has to understand one format.

Pure functions, no I/O — easy to unit test without a real OpenSearch/
Postgres connection (see tests/test_log_normalization.py).
"""

from datetime import datetime, timezone


# OpenCanary numeric logtypes we care about — see OpenCanary's
# opencanary/logger.py for the full list. Unrecognized codes fall back to
# a generic "connection" event rather than being dropped, so nothing
# silently disappears just because we haven't special-cased it yet.
OPENCANARY_LOGTYPE_MAP = {
    3000: "connection",          # PORTSCAN
    4001: "login_attempt",       # FTP_LOGIN_ATTEMPT
    6001: "login_attempt",       # HTTP_LOGIN_ATTEMPT
    9001: "login_attempt",       # MYSQL_LOGIN_ATTEMPT
    5001: "login_attempt",       # SMB_FILE_OPEN / auth-adjacent
}


def _parse_timestamp(value) -> datetime:
    """Accepts ISO8601 strings (with or without a trailing Z / fractional
    seconds) or a unix epoch, and always returns a timezone-aware UTC
    datetime — falls back to "now" for anything unparseable so a bad
    timestamp never crashes ingestion."""
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (ValueError, OSError):
            return datetime.now(timezone.utc)
    if isinstance(value, str):
        candidate = value.replace("Z", "+00:00")
        for fmt_attempt in (None, "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                if fmt_attempt is None:
                    return datetime.fromisoformat(candidate)
                return datetime.strptime(value, fmt_attempt)
            except ValueError:
                continue
    return datetime.now(timezone.utc)


def _base_event(source: str, raw: dict) -> dict:
    return {
        "source": source,
        "event_type": "unknown",
        "src_ip": "unknown",
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,
        "username": None,
        "password": None,
        "command": None,
        "ids_signature": None,
        "session_external_id": None,
        "occurred_at": datetime.now(timezone.utc),
        "raw_json": raw,
    }


def normalize_cowrie(raw: dict) -> dict | None:
    eventid = raw.get("eventid", "")
    type_map = {
        "cowrie.login.failed": "login_attempt",
        "cowrie.login.success": "login_success",
        "cowrie.command.input": "command",
        "cowrie.session.connect": "connection",
        "cowrie.session.closed": "session_closed",
    }
    event_type = type_map.get(eventid)
    if event_type is None:
        return None

    event = _base_event("cowrie", raw)
    event.update({
        "event_type": event_type,
        "src_ip": raw.get("src_ip", "unknown"),
        "dst_port": raw.get("dst_port"),
        "protocol": "ssh" if raw.get("dst_port") in (22, 2222) else "telnet",
        "username": raw.get("username"),
        "password": raw.get("password"),
        "command": raw.get("input"),
        "session_external_id": raw.get("session"),
        "occurred_at": _parse_timestamp(raw.get("timestamp")),
    })
    return event


def normalize_opencanary(raw: dict) -> dict | None:
    logtype = raw.get("logtype")
    event_type = OPENCANARY_LOGTYPE_MAP.get(logtype, "connection")

    logdata = raw.get("logdata", {}) or {}
    event = _base_event("opencanary", raw)
    event.update({
        "event_type": event_type,
        "src_ip": raw.get("src_host", "unknown"),
        "dst_ip": raw.get("dst_host"),
        "dst_port": raw.get("dst_port"),
        "username": logdata.get("USERNAME") or logdata.get("username"),
        "password": logdata.get("PASSWORD") or logdata.get("password"),
        "occurred_at": _parse_timestamp(raw.get("local_time") or raw.get("utc_time")),
    })
    return event


def normalize_dionaea(raw: dict) -> dict | None:
    event = _base_event("dionaea", raw)
    connection = raw.get("connection", raw)  # some Dionaea builds nest under "connection"
    event.update({
        "event_type": "malware_interaction",
        "src_ip": connection.get("remote_ip") or raw.get("src_ip", "unknown"),
        "dst_ip": connection.get("local_ip") or raw.get("dst_ip"),
        "dst_port": connection.get("local_port") or raw.get("dst_port"),
        "protocol": connection.get("protocol") or raw.get("connection_protocol"),
        "occurred_at": _parse_timestamp(raw.get("timestamp") or raw.get("time")),
    })
    return event


def normalize_zeek(raw: dict) -> dict | None:
    # Zeek's conn.log entries have "id.orig_h" / "id.resp_h" / "id.resp_p";
    # other log types (dns.log, http.log, ...) vary but always carry a
    # "ts" (unix epoch) and usually an originator/responder pair too.
    src_ip = raw.get("id.orig_h") or raw.get("id_orig_h")
    if not src_ip:
        return None  # not a connection-shaped Zeek log we know how to normalize yet

    event = _base_event("zeek", raw)
    event.update({
        "event_type": "connection",
        "src_ip": src_ip,
        "dst_ip": raw.get("id.resp_h") or raw.get("id_resp_h"),
        "dst_port": raw.get("id.resp_p") or raw.get("id_resp_p"),
        "protocol": raw.get("proto"),
        "occurred_at": _parse_timestamp(raw.get("ts")),
    })
    return event


def normalize_suricata(raw: dict) -> dict | None:
    if raw.get("event_type") != "alert":
        return None  # only alerts matter for detection; flow/dns/http noise is skipped

    alert = raw.get("alert", {}) or {}
    event = _base_event("suricata", raw)
    event.update({
        "event_type": "ids_alert",
        "src_ip": raw.get("src_ip", "unknown"),
        "dst_ip": raw.get("dest_ip"),
        "dst_port": raw.get("dest_port"),
        "protocol": raw.get("proto"),
        "ids_signature": alert.get("signature"),
        "occurred_at": _parse_timestamp(raw.get("timestamp")),
    })
    return event


NORMALIZERS = {
    "cowrie": normalize_cowrie,
    "opencanary": normalize_opencanary,
    "dionaea": normalize_dionaea,
    "zeek": normalize_zeek,
    "suricata": normalize_suricata,
}


def normalize(source: str, raw: dict) -> dict | None:
    """Single entry point the ingestion worker calls — dispatches to the
    right per-source parser. Returns None for events not worth persisting
    (e.g. Suricata "flow" records, unrecognized Zeek log types)."""
    normalizer = NORMALIZERS.get(source)
    if normalizer is None:
        return None
    return normalizer(raw)


