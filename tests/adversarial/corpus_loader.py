"""Adversarial corpus loader — thin re-export from aegis.bench.

The corpus and harness now live inside the installable `aegis.bench` package
so `aegis bench` works for `pip install`ed users. Tests import from this
shim for backwards compatibility.
"""

from aegis.bench import (
    Case,
    default_corpus_path,
    load_corpus,
    run_benchmark,
)

__all__ = ["Case", "default_corpus_path", "load_corpus", "run_benchmark"]
