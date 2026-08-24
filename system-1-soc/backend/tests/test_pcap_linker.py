"""
Unit tests for PCAP linking and BPF command building.
"""

from datetime import datetime, timedelta
from app.services import pcap_linker


def test_parse_pcap_filename():
    fn = "capture-20260824-140000.pcap"
    dt = pcap_linker.parse_pcap_filename(fn)
    assert dt is not None
    assert dt == datetime(2026, 8, 24, 14, 0, 0)


def test_find_pcap_files_for_window():
    files = [
        "capture-20260824-120000.pcap",
        "capture-20260824-130000.pcap",
        "capture-20260824-140000.pcap",
        "capture-20260824-150000.pcap",
    ]
    # Session from 13:15 to 13:45 -> covers 13:00 file
    start = datetime(2026, 8, 24, 13, 15, 0)
    end = datetime(2026, 8, 24, 13, 45, 0)
    matched = pcap_linker.find_pcap_files_for_window(files, start, end)
    assert matched == ["capture-20260824-130000.pcap"]

    # Session spanning 13:50 to 14:10 -> covers 13:00 and 14:00 files
    start_span = datetime(2026, 8, 24, 13, 50, 0)
    end_span = datetime(2026, 8, 24, 14, 10, 0)
    matched_span = pcap_linker.find_pcap_files_for_window(files, start_span, end_span)
    assert matched_span == ["capture-20260824-130000.pcap", "capture-20260824-140000.pcap"]


def test_build_extraction_command():
    sources = ["/var/log/pcap/capture-20260824-130000.pcap"]
    out = "/opt/evidence/sess1.pcap"
    cmd = pcap_linker.build_extraction_command(sources, out, "198.51.100.22", port=2222)
    assert cmd == ["tcpdump", "-r", sources[0], "-w", out, "host 198.51.100.22 and port 2222"]
