"""Reporter utilities — encoding helpers."""

from __future__ import annotations


def sanitize_surrogates(text: str) -> str:
    """Replace lone surrogates (U+D800-U+DFFF) with the Unicode replacement character.

    Python strings can contain lone surrogates (e.g. from Unicode smuggling
    payloads), but they cannot be encoded to UTF-8. This helper makes any
    string safe to write by round-tripping through surrogatepass encoding
    and then decoding with replace.
    """
    return text.encode("utf-8", errors="surrogatepass").decode("utf-8", errors="replace")
