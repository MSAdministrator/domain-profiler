"""Tests for typosquat / homoglyph detection (fully offline)."""

from domain_profiler.typosquat import Typosquat, normalize_homoglyphs, _similarity


class TestHelpers:
    def test_similarity_identical(self):
        assert _similarity("paypal", "paypal") == 1.0

    def test_similarity_unrelated(self):
        assert _similarity("paypal", "example") < 0.5

    def test_normalize_homoglyphs_digits(self):
        assert normalize_homoglyphs("paypa1") == "paypal"
        assert normalize_homoglyphs("g00gle") == "google"

    def test_normalize_homoglyphs_multichar(self):
        assert normalize_homoglyphs("rnicrosoft") == "microsoft"

    def test_normalize_homoglyphs_cyrillic(self):
        # Cyrillic 'а' (U+0430) folds to Latin 'a'.
        assert normalize_homoglyphs("pаypal") == "paypal"


class TestTyposquat:
    def test_identical_not_suspicious(self):
        r = Typosquat().analyze("paypal.com", "paypal.com")
        assert r["suspicious"] is False
        assert r["raw_similarity"] == 1.0

    def test_digit_swap_suspicious(self):
        r = Typosquat().analyze("paypa1.com", "paypal.com")
        assert r["suspicious"] is True
        assert r["identical_after_normalization"] is True

    def test_insertion_suspicious(self):
        r = Typosquat().analyze("gooogle.com", "google.com")
        assert r["suspicious"] is True
        assert r["normalized_similarity"] >= 0.75

    def test_unrelated_not_suspicious(self):
        r = Typosquat().analyze("example.org", "paypal.com")
        assert r["suspicious"] is False

    def test_idn_homograph_detected(self):
        # xn--pypal-4ve decodes to 'pаypal' (Cyrillic а).
        r = Typosquat().analyze("xn--pypal-4ve.com", "paypal.com")
        assert r["is_idn"] is True
        assert r["non_ascii"] is True
        assert r["suspicious"] is True
        assert r["identical_after_normalization"] is True

    def test_rn_to_m_homoglyph(self):
        r = Typosquat().analyze("rnicrosoft.com", "microsoft.com")
        assert r["suspicious"] is True

    def test_notes_present_for_suspicious(self):
        r = Typosquat().analyze("paypa1.com", "paypal.com")
        assert r["notes"]

    def test_inherits_from_base(self):
        from domain_profiler.base import Base
        assert isinstance(Typosquat(), Base)
