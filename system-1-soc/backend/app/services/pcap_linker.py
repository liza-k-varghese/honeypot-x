"""
PCAP Capture linking — Feature 111 (Digital Forensics).

System 2's tcpdump runs continuously, rotating to a new file every hour
(see system-2-honeypot/README.md's `-G 3600` setup) — so raw capture is
one big file per hour, not one file per session. This module bridges the
gap: given a session's time window, it finds the hourly pcap file(s) that
cover it, then shells out to tcpdump itself (as a *reader*, with -r) to
extract just that session's traffic — filtered by IP and port — into a
small, session-scoped pcap that becomes real Evidence.

Split the same way as elsewhere in this project: the matching/naming
logic is pure and testable without any pcap files or tcpdump binary
present; only `extract_session_pcap()` actually shells out.
"""

import hashlib
import os
import re
import subprocess
from datetime import datetime, timedelta

# Matches the naming pattern from system-2-honeypot's tcpdump systemd unit:
#   capture-YYYYMMDD-HHMMSS.pcap
PCAP_FILENAME_PATTERN = re.compile(r"capture-(\d{8})-(\d{6})\.pcap$")


def parse_pcap_filename(filename: str) -> datetime | None:
    """Extracts the capture-start timestamp embedded in a pcap filename,
    or None if the filename doesn't match the expected pattern (e.g. a
    stray file dropped into the same directory by something else)."""
    match = PCAP_FILENAME_PATTERN.search(filename)
    if not match:
        return None
    date_part, time_part = match.groups()
    try:
        return datetime.strptime(date_part + time_part, "%Y%m%d%H%M%S")
    except ValueError:
        return None


def find_pcap_files_for_window(
    available_filenames: list[str],
    session_start: datetime,
    session_end: datetime,
    rotation_interval: timedelta = timedelta(hours=1),
) -> list[str]:
    """Given every pcap filename in the capture directory, returns the
    ones whose rotation window overlaps [session_start, session_end].
    Pure function — takes a filename list rather than listing a directory
    itself, so it's testable without real pcap files on disk."""
    matches = []
    for filename in available_filenames:
        file_start = parse_pcap_filename(filename)
        if file_start is None:
            continue
        file_end = file_start + rotation_interval
        # Standard interval-overlap check: two ranges overlap unless one
        # ends before the other starts.
        if file_start < session_end and file_end > session_start:
            matches.append(filename)
    return sorted(matches)


def build_extraction_command(
    source_pcap_paths: list[str],
    output_path: str,
    src_ip: str,
    port: int | None = None,
) -> list[str]:
    """Builds the tcpdump command that would extract one session's
    traffic from the matched hourly capture(s). Returned as an argv list
    (not a shell string) — pure and testable, and safer than string
    concatenation since src_ip never passes through a shell.

    tcpdump can only read one input file at a time, so when a session
    spans a rotation boundary (rare, but possible for a long session
    right at the hour mark), the caller should run this once per matched
    file and merge with mergecap — see extract_session_pcap() below.
    """
    if not source_pcap_paths:
        raise ValueError("No source pcap files provided")

    bpf_filter = f"host {src_ip}"
    if port is not None:
        bpf_filter += f" and port {port}"

    return ["tcpdump", "-r", source_pcap_paths[0], "-w", output_path, bpf_filter]


def sha256_file(path: str, chunk_size: int = 65536) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def extract_session_pcap(
    capture_dir: str,
    output_dir: str,
    session_id: str,
    src_ip: str,
    session_start: datetime,
    session_end: datetime,
    port: int | None = None,
) -> dict | None:
    """End-to-end: find the right hourly capture(s), extract this
    session's traffic into its own small pcap, hash it, and return an
    Evidence-row-shaped dict — or None if no capture file covers this
    session's time window (e.g. tcpdump wasn't running yet, or the
    window has already aged out of the rotation).

    Requires the real `tcpdump` binary on PATH. If a session spans more
    than one hourly file, extracts from each and merges with `mergecap`
    (part of the Wireshark CLI tools — `apt install wireshark-common` if
    you don't already have it from the Suricata/Zeek setup).
    """
    available = [f for f in os.listdir(capture_dir) if f.endswith(".pcap")]
    matched = find_pcap_files_for_window(available, session_start, session_end)
    if not matched:
        return None

    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"session_{session_id}.pcap")

    if len(matched) == 1:
        cmd = build_extraction_command([os.path.join(capture_dir, matched[0])], output_path, src_ip, port)
        subprocess.run(cmd, check=True, capture_output=True, timeout=60)
    else:
        # Extract each matched file to a temp pcap, then merge.
        temp_paths = []
        for i, filename in enumerate(matched):
            temp_path = f"{output_path}.part{i}"
            cmd = build_extraction_command([os.path.join(capture_dir, filename)], temp_path, src_ip, port)
            subprocess.run(cmd, check=True, capture_output=True, timeout=60)
            temp_paths.append(temp_path)
        subprocess.run(["mergecap", "-w", output_path, *temp_paths], check=True, capture_output=True, timeout=60)
        for temp_path in temp_paths:
            os.remove(temp_path)

    if not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
        return None  # BPF filter matched nothing in this window — not an error, just no evidence to keep

    return {
        "evidence_type": "pcap",
        "file_path": output_path,
        "file_hash_sha256": sha256_file(output_path),
        "note_text": f"Extracted from {', '.join(matched)} — filter: host {src_ip}" + (f" and port {port}" if port else ""),
    }


