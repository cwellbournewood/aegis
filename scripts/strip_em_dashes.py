"""Replace em dashes across the repo with non-AI-tell punctuation.

Context-aware substitution:
    " — "  in middle of sentence  -> ". "  (start a new sentence)
    "X — Y" where Y starts lowercase -> "X, Y"
    "X — Y" where Y starts with capital or "—" is followed by a word that
        looks like an explanation -> "X. Y"

We don't try to fix capitalization downstream; the result is that some
sentences begin with a lowercase letter. Acceptable trade for not having
to rewrite every doc by hand.

Run with: python scripts/strip_em_dashes.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# File globs to clean. Skip the design/ reference HTML (it's a frozen artifact)
# and tests/adversarial/corpus.json (the corpus content uses em dashes inside
# attack strings; we don't want to mutate adversarial test data).
GLOBS = [
    "*.md",
    "docs/*.md",
    "aegis/**/*.py",
    "tests/**/*.py",
    "scripts/*.py",
    "ui/**/*.html",
]

EXCLUDE_PARTS = {"design", "node_modules", ".git", "egg-info", "dist", "__pycache__"}


def should_skip(path: Path) -> bool:
    parts = set(path.parts)
    if parts & EXCLUDE_PARTS:
        return True
    if path.name == "strip_em_dashes.py":
        return True
    return False


def replace_em_dashes(text: str) -> str:
    # Step 1: " — " (space, em dash, space) in the middle of a sentence.
    # If the next word starts with a lowercase letter, use a comma.
    # Otherwise, use a period to start a new sentence.
    def repl(match: re.Match[str]) -> str:
        following = match.group(1)
        if following and following[0].islower():
            return ", " + following
        return ". " + following

    text = re.sub(r" — (\S)", repl, text)

    # Step 2: stray em dashes attached to letters or in headers. Replace with a
    # colon when followed by an uppercase word that looks like a label, else a
    # period.
    text = re.sub(r"—(\S)", r" \1", text)
    text = re.sub(r"(\S)—", r"\1 ", text)

    # Step 3: any leftover em dashes (e.g. inside code fences or as bullet
    # separators that didn't match above) get replaced with a regular period.
    text = text.replace("—", ".")

    return text


def main() -> int:
    changed_files: list[Path] = []
    for pattern in GLOBS:
        for path in REPO.glob(pattern):
            if not path.is_file() or should_skip(path):
                continue
            try:
                original = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if "—" not in original:
                continue
            cleaned = replace_em_dashes(original)
            if cleaned != original:
                path.write_text(cleaned, encoding="utf-8")
                changed_files.append(path)

    print(f"cleaned {len(changed_files)} files")
    for p in sorted(changed_files):
        print(f"  {p.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
