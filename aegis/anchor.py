"""Intent Vector Anchoring.

Captures an embedding of the user's original request once per session/turn,
then computes cosine similarity between that anchor and the embeddings of
proposed tool calls. Drift below a threshold triggers WARN/BLOCK.

The default embedder is a deterministic local TF/character-n-gram embedder
(no torch dependency) so AEGIS works zero-config out of the box. For higher
quality, callers can install the `embed` extra (sentence-transformers) or
configure a hosted embedder via `hosted-embed`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Protocol

import numpy as np


@dataclass
class AnchorVector:
    """A vector + the raw text it was derived from."""

    text: str
    vector: np.ndarray
    model_id: str

    def __post_init__(self) -> None:
        norm = float(np.linalg.norm(self.vector))
        if norm > 0:
            self.vector = self.vector / norm


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


class IntentAnchor:
    """Manages anchor vectors and computes drift."""

    def __init__(
        self,
        embedder: Embedder | None = None,
        threshold_balanced: float = 0.30,
        threshold_strict: float = 0.45,
    ) -> None:
        self.embedder: Embedder = embedder or HashingEmbedder()
        self.threshold_balanced = threshold_balanced
        self.threshold_strict = threshold_strict

    def anchor(self, user_request: str) -> AnchorVector:
        vec = self.embedder.embed(user_request)
        return AnchorVector(text=user_request, vector=vec, model_id=self.embedder.model_id)

    def drift(
        self,
        action: ProposedAction,
        anchor: AnchorVector,
        mode: str = "balanced",
    ) -> DriftScore:
        action_text = action.to_text()
        action_vec = self.embedder.embed(action_text)
        sim = cosine(action_vec, anchor.vector)
        threshold = self.threshold_strict if mode == "strict" else self.threshold_balanced
        return DriftScore(
            similarity=sim,
            threshold=threshold,
            drifted=sim < threshold,
            anchor_text=anchor.text,
            action_text=action_text,
        )

    def drift_against_text(self, candidate: str, anchor: AnchorVector, mode: str = "balanced") -> DriftScore:
        cand_vec = self.embedder.embed(candidate)
        sim = cosine(cand_vec, anchor.vector)
        threshold = self.threshold_strict if mode == "strict" else self.threshold_balanced
        return DriftScore(
            similarity=sim,
            threshold=threshold,
            drifted=sim < threshold,
            anchor_text=anchor.text,
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
