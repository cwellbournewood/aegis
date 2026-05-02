"""Tests for the hash-chained DecisionLog."""

from __future__ import annotations

import json

from aegis.log import GENESIS_HASH, DecisionLog, iter_log, verify_log


def test_first_entry_has_genesis_prev_hash(tmp_path):
    log = DecisionLog(path=str(tmp_path / "log.jsonl"))
    e = log.append({"decision": "ALLOW", "request_id": "r1"})
    assert e.prev_hash == GENESIS_HASH
    assert e.seq == 1


def test_chain_links_sequential_entries(tmp_path):
    log = DecisionLog(path=str(tmp_path / "log.jsonl"))
    e1 = log.append({"decision": "ALLOW", "request_id": "r1"})
    e2 = log.append({"decision": "BLOCK", "request_id": "r2"})
    assert e2.prev_hash == e1.hash
    assert e2.seq == 2


def test_verify_log_accepts_clean(tmp_path):
    path = str(tmp_path / "log.jsonl")
    log = DecisionLog(path=path)
    for i in range(20):
        log.append({"decision": "ALLOW", "request_id": f"r{i}"})
    result = verify_log(path)
    assert result.ok
    assert result.entries_checked == 20


def test_verify_log_detects_tampering(tmp_path):
    path = str(tmp_path / "log.jsonl")
    log = DecisionLog(path=path)
    for i in range(5):
        log.append({"decision": "ALLOW", "request_id": f"r{i}"})

    # Mutate entry 3's payload after writing.
    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    entry = json.loads(lines[2])
    entry["payload"]["decision"] = "BLOCK"
    lines[2] = json.dumps(entry, separators=(",", ":")) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    result = verify_log(path)
    assert not result.ok
    assert result.broken_at == 3


def test_verify_log_detects_reorder(tmp_path):
    path = str(tmp_path / "log.jsonl")
    log = DecisionLog(path=path)
    for i in range(5):
        log.append({"decision": "ALLOW", "request_id": f"r{i}"})

    with open(path, encoding="utf-8") as fh:
        lines = fh.readlines()
    lines[1], lines[2] = lines[2], lines[1]
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)

    result = verify_log(path)
    assert not result.ok


def test_resume_from_existing_file(tmp_path):
    path = str(tmp_path / "log.jsonl")
    log = DecisionLog(path=path)
    log.append({"decision": "ALLOW", "request_id": "r1"})
    log.append({"decision": "WARN", "request_id": "r2"})

    log2 = DecisionLog(path=path)
    e3 = log2.append({"decision": "BLOCK", "request_id": "r3"})
    assert e3.seq == 3
    result = verify_log(path)
    assert result.ok
    assert result.entries_checked == 3


def test_find_by_request_id(tmp_path):
    log = DecisionLog(path=str(tmp_path / "log.jsonl"))
    log.append({"decision": "ALLOW", "request_id": "r1"})
    log.append({"decision": "BLOCK", "request_id": "r2"})
    found = log.find("r2")
    assert found is not None
    assert found.payload["request_id"] == "r2"


def test_in_memory_only_no_path():
    log = DecisionLog(path=None)
    log.append({"decision": "ALLOW", "request_id": "x"})
    assert len(log) == 1
    tail = log.tail(5)
    assert len(tail) == 1


def test_iter_log_yields_entries_in_order(tmp_path):
    path = str(tmp_path / "log.jsonl")
    log = DecisionLog(path=path)
    for i in range(10):
        log.append({"decision": "ALLOW", "request_id": f"r{i}"})
    seqs = [e.seq for e in iter_log(path)]
    assert seqs == list(range(1, 11))
