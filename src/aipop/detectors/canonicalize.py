"""Response canonicalization — decode obfuscation before classification.

Strips encoding layers that attackers (and models) use to sneak content
past keyword detectors: base64, hex, URL-encoding, HTML entities, and
Unicode tricks like zero-width characters and homoglyphs.

Run this BEFORE refusal detection or content matching.
"""

from __future__ import annotations

import base64
import html
import re
import unicodedata
from urllib.parse import unquote


# Zero-width and invisible Unicode characters that models sometimes emit
# (or that attackers inject) to break keyword matching.
_ZERO_WIDTH_CHARS = frozenset(
    "\u200b"  # ZERO WIDTH SPACE
    "\u200c"  # ZERO WIDTH NON-JOINER
    "\u200d"  # ZERO WIDTH JOINER
    "\u200e"  # LEFT-TO-RIGHT MARK
    "\u200f"  # RIGHT-TO-LEFT MARK
    "\u2060"  # WORD JOINER
    "\u2061"  # FUNCTION APPLICATION
    "\u2062"  # INVISIBLE TIMES
    "\u2063"  # INVISIBLE SEPARATOR
    "\u2064"  # INVISIBLE PLUS
    "\ufeff"  # BOM / ZERO WIDTH NO-BREAK SPACE
    "\ufe0f"  # VARIATION SELECTOR-16 (emoji modifier)
    "\ufe0e"  # VARIATION SELECTOR-15
)

# Common homoglyph mappings (Cyrillic/Greek → Latin).
# Not exhaustive — covers the most-abused substitutions.
_HOMOGLYPHS: dict[str, str] = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u041a": "K", "\u041c": "M", "\u041e": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x",
    # Greek
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N",
    "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
    "\u03b1": "a", "\u03b5": "e", "\u03bf": "o", "\u03c1": "p",
    # Fullwidth Latin
    "\uff21": "A", "\uff22": "B", "\uff23": "C", "\uff24": "D",
    "\uff25": "E", "\uff26": "F", "\uff27": "G", "\uff28": "H",
    "\uff29": "I", "\uff2a": "J", "\uff2b": "K", "\uff2c": "L",
    "\uff2d": "M", "\uff2e": "N", "\uff2f": "O", "\uff30": "P",
    "\uff31": "Q", "\uff32": "R", "\uff33": "S", "\uff34": "T",
    "\uff35": "U", "\uff36": "V", "\uff37": "W", "\uff38": "X",
    "\uff39": "Y", "\uff3a": "Z",
}

# Regex for inline base64 blobs (40+ chars, valid alphabet, optional padding)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# Regex for hex-encoded blobs (20+ hex pairs, common separators)
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}[\s:,]?){10,}")


def canonicalize(text: str) -> str:
    """Apply all canonicalization passes to *text* and return cleaned version.

    Order matters — decode nested encodings outside-in:
    1. Strip zero-width / invisible chars
    2. Normalize Unicode (NFC + homoglyphs)
    3. Decode HTML entities
    4. Decode URL-encoding
    5. Decode inline base64 blobs
    6. Decode inline hex blobs
    """
    text = _strip_zero_width(text)
    text = _normalize_unicode(text)
    text = _decode_html_entities(text)
    text = _decode_url_encoding(text)
    text = _decode_base64_blobs(text)
    text = _decode_hex_blobs(text)
    return text


def _strip_zero_width(text: str) -> str:
    """Remove zero-width and invisible Unicode characters."""
    return "".join(ch for ch in text if ch not in _ZERO_WIDTH_CHARS)


def _normalize_unicode(text: str) -> str:
    """NFC normalization + replace common homoglyphs with ASCII equivalents."""
    text = unicodedata.normalize("NFC", text)
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


def _decode_html_entities(text: str) -> str:
    """Decode HTML entities (e.g. &amp; → &, &#x41; → A)."""
    return html.unescape(text)


def _decode_url_encoding(text: str) -> str:
    """Decode percent-encoded sequences (e.g. %20 → space).

    Only decode if there are actual percent-encoded chars to avoid
    corrupting text that happens to contain literal percent signs.
    """
    if "%" in text and re.search(r"%[0-9a-fA-F]{2}", text):
        return unquote(text)
    return text


def _decode_base64_blobs(text: str) -> str:
    """Find and inline-decode base64 blobs.

    Only replaces blobs that decode to valid UTF-8 text. Binary blobs
    (images, compressed data) are left as-is — we only care about text
    that was base64'd to dodge keyword filters.
    """
    def _try_decode(match: re.Match) -> str:
        blob = match.group(0)
        # Require at least one non-letter char to avoid false positives
        # on long English words
        if not re.search(r"[0-9+/=]", blob):
            return blob
        try:
            decoded = base64.b64decode(blob, validate=True)
            decoded_text = decoded.decode("utf-8", errors="strict")
            # Sanity: if it decoded to mostly printable text, replace
            if sum(1 for c in decoded_text if c.isprintable() or c.isspace()) > len(decoded_text) * 0.7:
                return decoded_text
        except Exception:
            pass
        return blob

    return _BASE64_RE.sub(_try_decode, text)


def _decode_hex_blobs(text: str) -> str:
    """Find and inline-decode hex-encoded blobs.

    Only replaces when the hex decodes to valid UTF-8 text.
    """
    def _try_decode(match: re.Match) -> str:
        blob = match.group(0)
        # Strip common separators
        hex_str = re.sub(r"[\s:,]", "", blob)
        if len(hex_str) < 20:
            return blob
        try:
            decoded = bytes.fromhex(hex_str)
            decoded_text = decoded.decode("utf-8", errors="strict")
            if sum(1 for c in decoded_text if c.isprintable() or c.isspace()) > len(decoded_text) * 0.7:
                return decoded_text
        except Exception:
            pass
        return blob

    return _HEX_RE.sub(_try_decode, text)
