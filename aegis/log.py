"""Hash-chained, append-only decision log.

Each entry's `hash` covers (prev_hash || canonical_entry_bytes), giving a
tamper-evident chain. A verifier walks the file forward and confirms that no
entry was modified or removed.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass

GENESIS_HASH = "0" * 64


@dataclass
class LogEntry:
    seq: int
    timestamp: float
    prev_hash: str
    hash: str
    payload: dict


def _canonical_payload(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _compute_hash(prev_hash: str, seq: int, ts: float, payload: dict) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(str(seq).encode("ascii"))
    h.update(str(int(ts * 1000)).encode("ascii"))
    h.update(_canonical_payload(payload))
    return h.hexdigest()


class DecisionLog:
    """Append-only, hash-chained log on disk (one JSON per line, plus an in-memory tail)."""

    def __init__(self, path: str | None = None, retain_in_memory: int = 1024) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        self._tail: list[LogEntry] = []
        self._retain = retain_in_memory

        if path and os.path.exists(path):
            self._resume_from_file(path)

    def _resume_from_file(self, path: str) -> None:
        with open(path, encoding="utf-8") as fh:
            last = None
            count = 0
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    last = json.loads(line)
                    count += 1
                except json.JSONDecodeError:
                    continue
            if last is not None:
                self._seq = int(last["seq"])
                self._prev_hash = last["hash"]

    def append(self, payload: dict) -> LogEntry:
        with self._lock:
            self._seq += 1
            ts = time.time()
            digest = _compute_hash(self._prev_hash, self._seq, ts, payload)
            entry = LogEntry(seq=self._seq, timestamp=ts, prev_hash=self._prev_hash, hash=digest, payload=payload)
            self._prev_hash = digest
            self._tail.append(entry)
            if len(self._tail) > self._retain:
                self._tail = self._tail[-self._retain :]
            if self.path:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(
                        json.dumps(
                            {
                                "seq": entry.seq,
                                "ts": entry.timestamp,
                                "prev_hash": entry.prev_hash,
                                "hash": entry.hash,
                                "payload": entry.payload,
                            },
                            separators=(",", ":"),
                            default=str,
                        )
                        + "\n"
                    )
        return entry

    def tail(self, n: int = 50) -> list[LogEntry]:
        with self._lock:
            return list(self._tail[-n:])

    def find(self, request_id: str) -> LogEntry | None:
        with self._lock:
            for entry in reversed(self._tail):
                if entry.payload.get("request_id") == request_id:
                    return entry
        if self.path and os.path.exists(self.path):
            for entry in iter_log(self.path):
                if entry.payload.get("request_id") == request_id:
                    return entry
        return None

    def __len__(self) -> int:
        return self._seq


def iter_log(path: str) -> Iterator[LogEntry]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield LogEntry(
                seq=int(obj["seq"]),
                timestamp=float(obj["ts"]),
                prev_hash=obj["prev_hash"],
                hash=obj["hash"],
                payload=obj["payload"],
            )


@dataclass
class VerifyResult:
    ok: bool
    entries_checked: int
    broken_at: int | None = None
    reason: str = ""


def verify_log(path: str) -> VerifyResult:
    """Walk the file and verify the hash chain end-to-end."""
    prev_hash = GENESIS_HASH
    expected_seq = 0
    n = 0
    for entry in iter_log(path):
        expected_seq += 1
        n += 1
        if entry.seq != expected_seq:
            return VerifyResult(ok=False, entries_checked=n, broken_at=expected_seq, reason="seq gap or reorder")
        if entry.prev_hash != prev_hash:
            return VerifyResult(
                ok=False,
                entries_checked=n,
                broken_at=expected_seq,
                reason="prev_hash mismatch (entry tampered or out of order)",
            )
        recomputed = _compute_hash(prev_hash, entry.seq, entry.timestamp, entry.payload)
        if recomputed != entry.hash:
            return VerifyResult(
                ok=False,
                entries_checked=n,
                broken_at=expected_seq,
                reason="hash mismatch (entry tampered)",
            )
        prev_hash = entry.hash
    return VerifyResult(ok=True, entries_checked=n)
