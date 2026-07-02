"""Typosquatting and homoglyph detection against a known brand.

Given a candidate domain and a brand to compare against, this module scores how
likely the candidate is a deliberate look-alike of the brand. It combines:

* **string distance** — normalized Levenshtein similarity of the registrable
  labels (typosquats sit a small edit distance from the brand);
* **homoglyph normalization** — mapping visually-confusable characters (Cyrillic
  ``а`` → Latin ``a``, ``0`` → ``o``, etc.) so ``pаypal`` collapses onto
  ``paypal``;
* **IDN / punycode decoding** — an ``xn--`` label is decoded to Unicode so its
  homoglyph form is scored, and the presence of non-ASCII / mixed scripts is
  itself flagged.

Everything here is stdlib-only (no dnstwist/confusable-homoglyphs dependency);
the homoglyph map covers the common confusables used in real phishing.
"""

from typing import Any, Dict, List, Optional

from domain_profiler.base import Base


# Common visual confusables → their Latin lookalike. Enough to catch the
# homoglyph tricks seen in practice without pulling the full Unicode confusables
# table. Keys include Cyrillic/Greek look-alikes and digit/letter swaps.
HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic → Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "к": "k", "м": "m", "т": "t", "н": "h", "в": "b", "і": "i", "ѕ": "s",
    "ԁ": "d", "ј": "j", "ӏ": "l", "ԛ": "q", "ԝ": "w", "г": "r",
    # Greek → Latin
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t",
    "ε": "e", "χ": "x", "υ": "u",
    # digit / punctuation swaps
    "0": "o", "1": "l", "5": "s", "3": "e", "rn": "m", "vv": "w",
}


def _levenshtein(a: str, b: str) -> int:
    """Iterative Levenshtein edit distance (stdlib-only)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


def _similarity(a: str, b: str) -> float:
    """Normalized similarity in [0, 1] (1.0 == identical)."""
    if not a and not b:
        return 1.0
    longest = max(len(a), len(b))
    if longest == 0:
        return 1.0
    return 1.0 - _levenshtein(a, b) / longest


def normalize_homoglyphs(label: str) -> str:
    """Fold visually-confusable characters onto their Latin lookalike."""
    result = label.lower()
    # Multi-char sequences first (rn→m, vv→w), then single chars.
    for src, dst in HOMOGLYPH_MAP.items():
        if len(src) > 1:
            result = result.replace(src, dst)
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in result)


class Typosquat(Base):
    """Score a candidate domain's similarity to a known brand."""

    # A homoglyph-normalized similarity at/above this to the brand is suspicious.
    SUSPICIOUS_SIMILARITY: float = 0.75

    @staticmethod
    def _registrable_label(domain: str) -> str:
        """Return the second-level label (best-effort, no PSL dependency)."""
        parts = domain.strip().lower().rstrip(".").split(".")
        if len(parts) >= 2:
            return parts[-2]
        return parts[0] if parts else ""

    @staticmethod
    def _decode_idn(label: str) -> Dict[str, Any]:
        """Decode a punycode (xn--) label to Unicode; flag non-ASCII/mixed script."""
        info: Dict[str, Any] = {"decoded": label, "is_idn": False, "non_ascii": False}
        if label.startswith("xn--"):
            info["is_idn"] = True
            try:
                info["decoded"] = label.encode("ascii").decode("idna")
            except Exception:
                info["decoded"] = label
        info["non_ascii"] = any(ord(ch) > 127 for ch in info["decoded"])
        return info

    def analyze(self, domain: str, brand: str) -> Dict[str, Any]:
        """Score how likely ``domain`` is a typosquat/look-alike of ``brand``.

        Args:
            domain: The candidate domain to evaluate.
            brand: The legitimate brand domain (or label) to compare against.

        Returns:
            A dict with the raw and homoglyph-normalized similarity, IDN/script
            flags, a boolean ``suspicious`` verdict, and explanatory notes.
        """
        cand_label = self._registrable_label(domain)
        brand_label = self._registrable_label(brand)

        idn = self._decode_idn(cand_label)
        decoded_label = idn["decoded"]

        raw_similarity = _similarity(decoded_label, brand_label)
        normalized_candidate = normalize_homoglyphs(decoded_label)
        normalized_similarity = _similarity(normalized_candidate, brand_label)

        notes: List[str] = []
        exact_after_fold = (
            normalized_candidate == brand_label and decoded_label != brand_label
        )
        if exact_after_fold:
            notes.append(
                "Candidate is identical to the brand after homoglyph normalization"
            )
        if idn["is_idn"]:
            notes.append(f"Internationalized (punycode) domain decodes to '{decoded_label}'")
        if idn["non_ascii"]:
            notes.append("Label contains non-ASCII characters (possible homograph)")

        best_similarity = max(raw_similarity, normalized_similarity)
        suspicious = (
            decoded_label != brand_label
            and (best_similarity >= self.SUSPICIOUS_SIMILARITY or exact_after_fold)
        )
        if suspicious and not notes:
            notes.append(
                f"Label '{decoded_label}' is {best_similarity:.0%} similar to brand '{brand_label}'"
            )

        return {
            "domain": domain,
            "brand": brand,
            "candidate_label": cand_label,
            "decoded_label": decoded_label,
            "brand_label": brand_label,
            "raw_similarity": round(raw_similarity, 3),
            "normalized_similarity": round(normalized_similarity, 3),
            "is_idn": idn["is_idn"],
            "non_ascii": idn["non_ascii"],
            "identical_after_normalization": exact_after_fold,
            "suspicious": suspicious,
            "notes": notes,
        }
