"""Intent Vector Anchoring.

Captures embeddings of the user's request(s) for a session, then computes
cosine similarity between the highest-matching anchor and the embeddings of
proposed tool calls. Drift below a threshold triggers WARN/BLOCK.

The default embedder is a deterministic local TF/character-n-gram embedder
(no torch dependency) so AEGIS works zero-config out of the box. For higher
quality, callers can install the `embed` extra (sentence-transformers) or
configure a hosted embedder via `hosted-embed`.

False-positive mitigation:
    - Multi-anchor: a session can accumulate multiple anchor vectors (one per
      user turn). Drift is scored against the *closest* anchor, so multi-step
      tasks don't trigger drift just because the user changed sub-task.
    - LRU embedding cache: repeated text inputs hit the embedder once per
      process, reducing latency for chatty agentic loops.
"""

from __future__ import annotations

import hashlib
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Protocol

import numpy as np


@dataclass
class AnchorVector:
    """A vector + the raw text it was derived from.

    For backwards compatibility, AnchorVector represents either a single anchor
    (text + vector) or, when used as a multi-anchor container, a stack of
    additional `texts`/`vectors`. `IntentAnchor.drift` always picks the best
    match across all anchors.
    """

    text: str
    vector: np.ndarray
    model_id: str
    texts: list[str] = field(default_factory=list)
    vectors: list[np.ndarray] = field(default_factory=list)

    def __post_init__(self) -> None:
        norm = float(np.linalg.norm(self.vector))
        if norm > 0:
            self.vector = self.vector / norm
        # Initialize multi-anchor list with the primary anchor.
        if not self.texts:
            self.texts = [self.text]
            self.vectors = [self.vector]

    def add(self, text: str, vector: np.ndarray) -> None:
        """Append a new anchor (e.g., when user moves to a new sub-task)."""
        norm = float(np.linalg.norm(vector))
        if norm > 0:
            vector = vector / norm
        # De-dup on text, repeated identical user messages don't multiply anchors.
        if text in self.texts:
            return
        self.texts.append(text)
        self.vectors.append(vector)

    @property
    def all_vectors(self) -> list[np.ndarray]:
        return self.vectors if self.vectors else [self.vector]


class Embedder(Protocol):
    model_id: str

    def embed(self, text: str) -> np.ndarray: ...


class HashingEmbedder:
    """Deterministic local embedder.

    Produces fixed-dimensional vectors via feature hashing over character and
    word n-grams. Quality is far below a real transformer embedder, but it has
    three useful properties for v1 default: zero install footprint, fully
    deterministic (so tests are stable), and "in the right neighborhood" for
    paraphrase vs. wholly-unrelated-task discrimination.

    Anyone serious about intent-anchoring quality should swap in
    `SentenceTransformerEmbedder` via the `embed` extra.
    """

    def __init__(self, dim: int = 384) -> None:
        self.dim = dim
        self.model_id = f"aegis-hashing-{dim}"
        self._token_re = re.compile(r"[A-Za-z][A-Za-z\-']+|\d+")

    def _features(self, text: str) -> list[tuple[str, float]]:
        text_lower = text.lower().strip()
        if not text_lower:
            return []

        feats: list[tuple[str, float]] = []
        tokens = self._token_re.findall(text_lower)

        for tok in tokens:
            feats.append(("w1:" + tok, 1.0))

        for i in range(len(tokens) - 1):
            feats.append(("w2:" + tokens[i] + "_" + tokens[i + 1], 0.7))

        cleaned = re.sub(r"\s+", " ", text_lower)
        for n in (3, 4, 5):
            for i in range(len(cleaned) - n + 1):
                feats.append((f"c{n}:{cleaned[i:i+n]}", 0.4 / n))

        for tok in set(tokens):
            feats.append(("v:" + tok, 0.3))

        return feats

    def embed(self, text: str) -> np.ndarray:
        vec = np.zeros(self.dim, dtype=np.float32)
        for feat, weight in self._features(text):
            digest = hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest()
            idx = int.from_bytes(digest[:4], "big") % self.dim
            sign = 1.0 if (digest[4] & 1) else -1.0
            vec[idx] += sign * weight
        norm = float(np.linalg.norm(vec))
        if norm > 0:
            vec = vec / norm
        return vec


class SentenceTransformerEmbedder:
    """Wrapper around `sentence-transformers` if installed.

    Default model: all-MiniLM-L6-v2 (~80MB, CPU-friendly, 384 dim).
    """

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2") -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise ImportError(
                "SentenceTransformerEmbedder requires the 'embed' extra: "
                "pip install 'aegis-guard[embed]'"
            ) from exc
        self._model = SentenceTransformer(model_name)
        self.model_id = model_name

    def embed(self, text: str) -> np.ndarray:
        vec = self._model.encode([text], convert_to_numpy=True, normalize_embeddings=True)[0]
        return np.asarray(vec, dtype=np.float32)


def cosine(a: np.ndarray, b: np.ndarray) -> float:
    na = float(np.linalg.norm(a))
    nb = float(np.linalg.norm(b))
    if na == 0 or nb == 0:
        return 0.0
    return float(np.dot(a, b) / (na * nb))


@dataclass
class ProposedAction:
    """The thing we want to score against the anchor."""

    tool_name: str
    parameters: dict[str, Any]
    summary: str | None = None

    def to_text(self) -> str:
        if self.summary:
            return self.summary
        try:
            param_str = " ".join(f"{k}={v}" for k, v in self.parameters.items())
        except Exception:
            param_str = str(self.parameters)
        return f"call {self.tool_name} with {param_str}"


@dataclass
class DriftScore:
    similarity: float
    threshold: float
    drifted: bool
    anchor_text: str
    action_text: str


class _LRUCache:
    """Tiny thread-safe LRU for embedded vectors. Avoids re-embedding the same
    text within a process, repeated user messages and tool-call summaries are
    common in agentic loops."""

    def __init__(self, capacity: int = 1024) -> None:
        self.capacity = capacity
        self._data: OrderedDict[str, np.ndarray] = OrderedDict()
        self._lock = Lock()

    def get(self, key: str) -> np.ndarray | None:
        with self._lock:
            v = self._data.get(key)
            if v is not None:
                self._data.move_to_end(key)
            return v

    def put(self, key: str, value: np.ndarray) -> None:
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            else:
                self._data[key] = value
                if len(self._data) > self.capacity:
                    self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()


class IntentAnchor:
    """Manages anchor vectors and computes drift.

    Caches embeddings via LRU (default capacity 1024) so repeated text inputs
    don't re-run the embedder. Supports multi-anchor sessions: drift is scored
    against the best-matching anchor among all the user has expressed.
    """

    def __init__(
        self,
        embedder: Embedder | None = None,
        threshold_balanced: float = 0.22,
        threshold_strict: float = 0.40,
        cache_size: int = 1024,
    ) -> None:
        self.embedder: Embedder = embedder or HashingEmbedder()
        self.threshold_balanced = threshold_balanced
        self.threshold_strict = threshold_strict
        self._cache = _LRUCache(capacity=cache_size)

    def _embed_cached(self, text: str) -> np.ndarray:
        cached = self._cache.get(text)
        if cached is not None:
            return cached
        vec = self.embedder.embed(text)
        self._cache.put(text, vec)
        return vec

    def anchor(self, user_request: str) -> AnchorVector:
        vec = self._embed_cached(user_request)
        return AnchorVector(text=user_request, vector=vec, model_id=self.embedder.model_id)

    def add_anchor(self, anchor: AnchorVector, additional_text: str) -> None:
        """Mutate an existing anchor to include a new user-intent text.

        Used by the orchestrator when a user adds a new turn, the proposed
        action will be scored against the *closest* anchor across the session,
        which substantially reduces FPs on legitimate multi-step workflows.
        """
        if not additional_text or additional_text.strip() == "":
            return
        vec = self._embed_cached(additional_text)
        anchor.add(additional_text, vec)

    def drift(
        self,
        action: ProposedAction,
        anchor: AnchorVector,
        mode: str = "balanced",
    ) -> DriftScore:
        action_text = action.to_text()
        action_vec = self._embed_cached(action_text)
        # Score against ALL anchors, take the highest similarity. This is the
        # multi-step drift dampener: as long as the action aligns with any
        # past user intent, it isn't drift.
        sims = [cosine(action_vec, v) for v in anchor.all_vectors]
        sim = max(sims) if sims else 0.0
        best_idx = sims.index(sim) if sims else 0
        anchor_text = anchor.texts[best_idx] if anchor.texts else anchor.text
        threshold = self.threshold_strict if mode == "strict" else self.threshold_balanced
        return DriftScore(
            similarity=sim,
            threshold=threshold,
            drifted=sim < threshold,
            anchor_text=anchor_text,
            action_text=action_text,
        )

    def drift_against_text(self, candidate: str, anchor: AnchorVector, mode: str = "balanced") -> DriftScore:
        cand_vec = self._embed_cached(candidate)
        sims = [cosine(cand_vec, v) for v in anchor.all_vectors]
        sim = max(sims) if sims else 0.0
        best_idx = sims.index(sim) if sims else 0
        anchor_text = anchor.texts[best_idx] if anchor.texts else anchor.text
        threshold = self.threshold_strict if mode == "strict" else self.threshold_balanced
        return DriftScore(
            similarity=sim,
            threshold=threshold,
            drifted=sim < threshold,
            anchor_text=anchor_text,
            action_text=candidate,
        )


def make_default_embedder() -> Embedder:
    return HashingEmbedder()


def make_embedder_from_config(config: dict[str, Any]) -> Embedder:
    """Construct an embedder from a config dict.

    Config keys:
        kind: "hashing" | "sentence-transformers" | "openai"
        model: model name (for st / openai)
        dim: dim (for hashing)
    """
    kind = config.get("kind", "hashing")
    if kind == "hashing":
        return HashingEmbedder(dim=int(config.get("dim", 384)))
    if kind in {"sentence-transformers", "st"}:
        return SentenceTransformerEmbedder(
            model_name=config.get("model", "sentence-transformers/all-MiniLM-L6-v2")
        )
    raise ValueError(f"unknown embedder kind: {kind}")
