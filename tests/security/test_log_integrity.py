"""Security tests: tamper attempts on the hash-chained decision log.

Verify that all classes of mutation are caught: tampering, truncation,
insertion, reorder, timestamp manipulation.
"""

from __future__ import annotations

import json

from aegis.log import DecisionLog, verify_log


def _make_log(tmp_path, n: int = 10) -> str:
    path = str(tmp_path / "log.jsonl")
    log = DecisionLog(path=path)
    for i in range(n):
        log.append({"decision": "ALLOW", "request_id": f"r{i}", "session_id": "s"})
    return path


def test_clean_log_verifies(tmp_path):
    path = _make_log(tmp_path, n=20)
    r = verify_log(path)
    assert r.ok and r.entries_checked == 20


def test_payload_tamper_detected(tmp_path):
    path = _make_log(tmp_path, n=10)
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    obj = json.loads(lines[5])
    obj["payload"]["decision"] = "BLOCK"
    lines[5] = json.dumps(obj, separators=(",", ":")) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    r = verify_log(path)
    assert not r.ok
    assert r.broken_at == 6  # 1-indexed: position 5 in zero-based file lines is seq 6


def test_hash_field_tamper_detected(tmp_path):
    """Recompute and substitute the hash with the right algorithm — but you can't
    because you don't know the prev_hash unless you also know everything before."""
    path = _make_log(tmp_path, n=5)
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    obj = json.loads(lines[2])
    obj["hash"] = "0" * 64  # forge
    lines[2] = json.dumps(obj, separators=(",", ":")) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    r = verify_log(path)
    assert not r.ok


def test_prev_hash_tamper_detected(tmp_path):
    path = _make_log(tmp_path, n=5)
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    obj = json.loads(lines[2])
    obj["prev_hash"] = "0" * 64
    lines[2] = json.dumps(obj, separators=(",", ":")) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    r = verify_log(path)
    assert not r.ok


def test_timestamp_tamper_detected(tmp_path):
    """Timestamp is part of the hash input — modifying it breaks the chain."""
    path = _make_log(tmp_path, n=5)
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    obj = json.loads(lines[2])
    obj["ts"] = obj["ts"] + 1000.0
    lines[2] = json.dumps(obj, separators=(",", ":")) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    r = verify_log(path)
    assert not r.ok


def test_truncation_at_end_detected_via_tip_pointer(tmp_path):
    """Hash chain + sidecar tip pointer → truncation IS detectable.

    `verify_log` reads the `<path>.tip` file written on each append, and
    if its claimed seq exceeds the file's terminal seq, raises FAIL.
    """
    path = _make_log(tmp_path, n=10)
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    # Drop the last 3 entries.
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines[:-3])
    r = verify_log(path)
    assert not r.ok
    assert "truncation" in r.reason
    assert r.broken_at == 8  # the missing seq


def test_truncation_with_check_tip_false_still_walks_remaining(tmp_path):
    """Forensic / archival mode: skip the tip check, walk what's there."""
    path = _make_log(tmp_path, n=10)
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines[:-3])
    r = verify_log(path, check_tip=False)
    assert r.ok
    assert r.entries_checked == 7


def test_terminal_entry_swap_detected_via_tip(tmp_path):
    """Replace the last entry with a forged-but-self-consistent one. The chain
    walk would accept it (no chain reference outward), but the tip catches it."""
    path = _make_log(tmp_path, n=5)
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    # Forge a new last entry that re-uses the prior prev_hash so the chain is "valid".
    obj = json.loads(lines[-1])
    forged = dict(obj)
    forged["payload"] = {"decision": "ALLOW", "request_id": "FORGED"}
    # Recompute the hash so the chain itself is valid.
    from aegis.log import _compute_hash

    forged["hash"] = _compute_hash(forged["prev_hash"], forged["seq"], forged["ts"], forged["payload"])
    lines[-1] = json.dumps(forged, separators=(",", ":")) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    # Without the tip, this looks valid.
    no_tip = verify_log(path, check_tip=False)
    assert no_tip.ok
    # With the tip, the swap is caught.
    with_tip = verify_log(path)
    assert not with_tip.ok
    assert "tip hash mismatch" in with_tip.reason


def test_insertion_at_middle_detected(tmp_path):
    """Insert a synthetic entry — chain breaks because seq jumps."""
    path = _make_log(tmp_path, n=5)
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    # Insert a fake entry at position 3.
    fake = {
        "seq": 999,
        "ts": 1234567890.0,
        "prev_hash": "0" * 64,
        "hash": "1" * 64,
        "payload": {"decision": "ALLOW", "request_id": "fake"},
    }
    lines.insert(3, json.dumps(fake, separators=(",", ":")) + "\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    r = verify_log(path)
    assert not r.ok


def test_reorder_two_entries_detected(tmp_path):
    path = _make_log(tmp_path, n=5)
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    lines[1], lines[2] = lines[2], lines[1]
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)
    r = verify_log(path)
    assert not r.ok


def test_concurrent_appends_dont_corrupt_chain(tmp_path):
    """Append from multiple threads — chain must remain consistent."""
    import threading

    path = str(tmp_path / "log.jsonl")
    log = DecisionLog(path=path)

    def worker(start: int):
        for i in range(50):
            log.append({"decision": "ALLOW", "request_id": f"t{start}_r{i}"})

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    r = verify_log(path)
    assert r.ok
    assert r.entries_checked == 200


def test_resume_from_existing_log_continues_chain(tmp_path):
    path = _make_log(tmp_path, n=5)
    log2 = DecisionLog(path=path)
    log2.append({"decision": "BLOCK", "request_id": "later"})
    r = verify_log(path)
    assert r.ok
    assert r.entries_checked == 6


def test_corrupt_json_line_skipped_resume_correctly(tmp_path):
    """If the file has a corrupt line (e.g., partial write), the resume reads
    the latest *valid* entry. This is a robustness property."""
    path = _make_log(tmp_path, n=5)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("{not valid json\n")
    log2 = DecisionLog(path=path)
    # Should resume from seq 5 (the last valid entry).
    e = log2.append({"decision": "ALLOW", "request_id": "next"})
    assert e.seq == 6
