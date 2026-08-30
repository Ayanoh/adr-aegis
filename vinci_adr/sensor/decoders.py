"""Deobfuscation and decoding engine for the Vinci ADR sensor layer.

This module provides functions to counter evasion techniques such as invisible Unicode
characters, homoglyphs, URL percent-encoding, multi-layer Base64/Hex encoding, and ROT13 ciphers.
"""

import base64
import binascii
import codecs
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field

# Zero-width and invisible Unicode characters to remove
INVISIBLE_CHARS: list[str] = [
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\u2060",  # Word joiner
    "\ufeff",  # Zero-width no-break space (BOM)
    "\u00ad",  # Soft hyphen
    "\u034f",  # Combining grapheme joiner
    "\u061c",  # Arabic letter mark
    "\u115f",  # Hangul choseong filler
    "\u1160",  # Hangul jungseong filler
    "\u17b4",  # Khmer vowel inherent AQ
    "\u17b5",  # Khmer vowel inherent AA
    "\u180e",  # Mongolian vowel separator
    "\u2000",  # En quad
    "\u2001",  # Em quad
    "\u2002",  # En space
    "\u2003",  # Em space
    "\u2004",  # Three-per-em space
    "\u2005",  # Four-per-em space
    "\u2006",  # Six-per-em space
    "\u2007",  # Figure space
    "\u2008",  # Punctuation space
    "\u2009",  # Thin space
    "\u200a",  # Hair space
    "\u202f",  # Narrow no-break space
    "\u205f",  # Medium mathematical space
    "\u3000",  # Ideographic space
]

INVISIBLE_CHARS_SET: set[str] = set(INVISIBLE_CHARS)

# Mapping of common homoglyphs (Cyrillic, Greek, math, etc.) to standard ASCII
HOMOGLYPH_MAP: dict[str, str] = {
    "а": "a",  # Cyrillic small a
    "е": "e",  # Cyrillic small e
    "о": "o",  # Cyrillic small o
    "р": "p",  # Cyrillic small r
    "с": "c",  # Cyrillic small c
    "х": "x",  # Cyrillic small x
    "А": "A",  # Cyrillic capital A
    "В": "B",  # Cyrillic capital V (looks like B)
    "Е": "E",  # Cyrillic capital E
    "К": "K",  # Cyrillic capital K
    "М": "M",  # Cyrillic capital M
    "Н": "H",  # Cyrillic capital N (looks like H)
    "О": "O",  # Cyrillic capital O
    "Р": "P",  # Cyrillic capital R (looks like P)
    "С": "C",  # Cyrillic capital S (looks like C)
    "Т": "T",  # Cyrillic capital T
    "Х": "X",  # Cyrillic capital X
    "ᴀ": "A",  # Small capital A
    "ᴇ": "E",  # Small capital E
    "ɪ": "I",  # Latin small capital I
    "ʀ": "R",  # Small capital R
    "ꜱ": "S",  # Small capital S
    # Greek
    "α": "a",  # Greek small alpha
    "ο": "o",  # Greek small omicron
    "ρ": "p",  # Greek small rho
    # Math symbols
    "ℯ": "e",  # Script small e
    "ℓ": "l",  # Script small l
}

# Regex pattern for base64 detection (matches valid base64 tokens >= 4 chars)
BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){1,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

# Regex pattern for hex string detection (even length, min 4 hex characters)
HEX_PATTERN = re.compile(r"(?:0x)?([A-Fa-f0-9]{4,})")

# Regex pattern for URL percent-encoded characters (%XX)
URL_ENCODED_PATTERN = re.compile(r"(?:%[0-9a-fA-F]{2})+")

# Suspicious keywords for ROT13 detection heuristic
ROT13_SUSPICIOUS_KEYWORDS: set[str] = {
    "curl",
    "wget",
    "bash",
    "sh",
    "ignore",
    "password",
    "secret",
    "admin",
    "root",
    "system",
    "exec",
    "chmod",
    "rm",
    "cat",
    "eval",
    "python",
    "shadow",
    "sudo",
}


@dataclass
class DecodedResult:
    """Result of a decoding operation.

    Attributes:
        original: The original input string.
        decoded: The decoded/normalized string.
        transformations: List of transformations applied (e.g., ["base64", "unicode_normalize"]).
        is_suspicious: True if decoding revealed hidden content.
    """

    original: str
    decoded: str
    transformations: list[str] = field(default_factory=list)
    is_suspicious: bool = False


def remove_invisible_chars(text: str) -> tuple[str, bool]:
    """Removes invisible and zero-width characters from input text.

    Args:
        text: Input string potentially containing invisible characters.

    Returns:
        Tuple containing (cleaned_text, was_modified).

    Example:
        >>> remove_invisible_chars("c\\u200ba\\u200bt")
        ('cat', True)
    """
    if not isinstance(text, str) or not text:
        return text, False

    cleaned = "".join(ch for ch in text if ch not in INVISIBLE_CHARS_SET)
    return cleaned, cleaned != text


def normalize_unicode(text: str) -> tuple[str, bool]:
    """Normalizes Unicode text via NFKC representation and converts full-width chars.

    Args:
        text: Input string with potential Unicode homoglyphs.

    Returns:
        Tuple containing (normalized_text, was_modified).

    Example:
        >>> normalize_unicode("Ｉｇｎｏｒｅ")
        ('Ignore', True)
    """
    if not isinstance(text, str) or not text:
        return text, False

    normalized = unicodedata.normalize("NFKC", text)
    return normalized, normalized != text


def normalize_homoglyphs(text: str) -> tuple[str, bool]:
    """Replaces common Cyrillic, Greek, and other Unicode homoglyphs with standard ASCII chars.

    Args:
        text: Input string with potential homoglyphs.

    Returns:
        Tuple containing (normalized_text, was_modified).

    Example:
        >>> normalize_homoglyphs("ехес")
        ('exec', True)
    """
    if not isinstance(text, str) or not text:
        return text, False

    chars = [HOMOGLYPH_MAP.get(ch, ch) for ch in text]
    normalized = "".join(chars)
    return normalized, normalized != text


def decode_url_encoding(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Decodes URL percent-encoded (%XX) sequences within text.

    Args:
        text: Input text containing potential percent-encoded sequences.

    Returns:
        Tuple of (decoded_text, list_of_replacements).

    Example:
        >>> decode_url_encoding("%63%75%72%6C")
        ('curl', [('%63%75%72%6C', 'curl')])
    """
    if not isinstance(text, str) or "%" not in text:
        return text, []

    matches = list(URL_ENCODED_PATTERN.finditer(text))
    if not matches:
        return text, []

    replacements: list[tuple[str, str]] = []
    modified_text = text

    for match in matches:
        encoded_seq = match.group(0)
        try:
            decoded_seq = urllib.parse.unquote(encoded_seq)
            if decoded_seq != encoded_seq:
                replacements.append((encoded_seq, decoded_seq))
        except (ValueError, UnicodeDecodeError):
            continue

    if replacements:
        for enc, dec in sorted(set(replacements), key=lambda x: len(x[0]), reverse=True):
            modified_text = modified_text.replace(enc, dec)

    return modified_text, replacements


def decode_base64(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Finds and decodes valid Base64 segments embedded within text.

    Args:
        text: Input text containing potential Base64 payloads.

    Returns:
        Tuple of (modified_text, list_of_replacements) where each replacement
        is a tuple (original_b64, decoded_utf8_text).

    Example:
        >>> decode_base64("Y3VybA==")
        ('curl', [('Y3VybA==', 'curl')])
    """
    if not isinstance(text, str) or not text.strip():
        return text, []

    replacements: list[tuple[str, str]] = []
    modified_text = text

    candidates = BASE64_PATTERN.findall(text)

    for candidate in sorted(set(candidates), key=len, reverse=True):
        if (len(candidate) < 8 and not candidate.endswith("=")) or candidate.isdigit():
            continue
        try:
            raw_bytes = base64.b64decode(candidate, validate=True)
            decoded_str = raw_bytes.decode("utf-8")
            if (
                all(c.isprintable() or c in "\r\n\t " for c in decoded_str)
                and len(decoded_str) > 0
                and decoded_str != candidate
            ):
                modified_text = modified_text.replace(candidate, decoded_str)
                replacements.append((candidate, decoded_str))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue

    return modified_text, replacements


def decode_base64_recursive(
    text: str, max_depth: int = 3
) -> tuple[str, list[tuple[str, str]], int]:
    """Decodes Base64 payloads recursively up to max_depth levels.

    Args:
        text: Input text containing nested Base64 payloads.
        max_depth: Maximum levels of recursion.

    Returns:
        Tuple of (decoded_text, all_replacements, depth_reached).

    Example:
        >>> decode_base64_recursive("WTNWeWJBPT0=")
        ('curl', [('WTNWeWJBPT0=', 'Y3VybA=='), ('Y3VybA==', 'curl')], 2)
    """
    if not isinstance(text, str) or not text.strip():
        return text, [], 0

    current = text
    all_replacements: list[tuple[str, str]] = []
    depth_reached = 0

    for depth in range(1, max_depth + 1):
        decoded_text, replacements = decode_base64(current)
        if not replacements or decoded_text == current:
            break
        current = decoded_text
        all_replacements.extend(replacements)
        depth_reached = depth

    return current, all_replacements, depth_reached


def decode_hex(text: str) -> tuple[str, list[tuple[str, str]]]:
    """Finds and decodes valid Hexadecimal segments within text.

    Args:
        text: Input text containing potential Hex payloads.

    Returns:
        Tuple of (modified_text, list_of_replacements) where each replacement
        is a tuple (original_hex, decoded_utf8_text).

    Example:
        >>> decode_hex("0x726d202d7266")
        ('rm -rf', [('0x726d202d7266', 'rm -rf')])
    """
    if not isinstance(text, str) or not text.strip():
        return text, []

    replacements: list[tuple[str, str]] = []
    modified_text = text

    for match in HEX_PATTERN.finditer(text):
        full_match = match.group(0)
        hex_digits = match.group(1)

        if len(hex_digits) % 2 != 0 or len(hex_digits) < 4:
            continue

        try:
            raw_bytes = bytes.fromhex(hex_digits)
            decoded_str = raw_bytes.decode("utf-8")
            if (
                all(c.isprintable() or c in "\r\n\t " for c in decoded_str)
                and len(decoded_str) > 0
                and decoded_str != full_match
            ):
                modified_text = modified_text.replace(full_match, decoded_str)
                replacements.append((full_match, decoded_str))
        except (ValueError, UnicodeDecodeError):
            continue

    return modified_text, replacements


def decode_rot13(text: str) -> str:
    """Applies ROT13 transformation to input text.

    Args:
        text: Input string.

    Returns:
        ROT13 decoded/encoded string.

    Example:
        >>> decode_rot13("phey")
        'curl'
    """
    if not isinstance(text, str):
        return text
    try:
        return codecs.decode(text, "rot_13")
    except (ValueError, TypeError, LookupError):
        return text


def detect_rot13(text: str) -> tuple[bool, str]:
    """Detects whether text appears to be obfuscated using ROT13.

    Args:
        text: Input text to evaluate.

    Returns:
        Tuple of (is_rot13_encoded, decoded_text if suspicious else original).

    Example:
        >>> detect_rot13("phey http://evil.com")
        (True, 'curl http://evil.com')
    """
    if not isinstance(text, str) or not text.strip():
        return False, text

    decoded = decode_rot13(text)

    def count_keywords(s: str) -> int:
        words = set(re.findall(r"[a-zA-Z]{2,}", s.lower()))
        return len(words.intersection(ROT13_SUSPICIOUS_KEYWORDS))

    count_orig = count_keywords(text)
    count_decoded = count_keywords(decoded)

    if count_decoded > count_orig and count_decoded > 0:
        return True, decoded

    return False, text


def decode_all(text: str, max_iterations: int = 5) -> DecodedResult:
    """Executes the complete anti-evasion decoding and normalization pipeline.

    Sequentially applies:
    1. remove_invisible_chars
    2. normalize_unicode (NFKC)
    3. normalize_homoglyphs (homoglyph dictionary map)
    4. decode_url_encoding (percent-encoding %XX)
    5. decode_base64_recursive (recursive Base64 with max_depth=3)
    6. decode_hex (Hexadecimal sequences)
    7. detect_rot13 (ROT13 heuristic cipher)

    Iterates until stabilization or max_iterations is reached.

    Args:
        text: Raw input string.
        max_iterations: Maximum iterations for pipeline stabilization.

    Returns:
        DecodedResult with final decoded text, list of transformations, and is_suspicious flag.
    """
    if not isinstance(text, str) or not text:
        return DecodedResult(original=text, decoded=text)

    current = text
    transformations: list[str] = []
    is_suspicious = False

    for _ in range(max_iterations):
        prev = current

        # 1. Remove invisible characters
        current, mod_inv = remove_invisible_chars(current)
        if mod_inv and "remove_invisible_chars" not in transformations:
            transformations.append("remove_invisible_chars")
            is_suspicious = True

        # 2. Normalize Unicode (NFKC)
        current, mod_uni = normalize_unicode(current)
        if mod_uni and "normalize_unicode" not in transformations:
            transformations.append("normalize_unicode")
            is_suspicious = True

        # 3. Normalize Homoglyphs
        current, mod_homo = normalize_homoglyphs(current)
        if mod_homo and "normalize_homoglyphs" not in transformations:
            transformations.append("normalize_homoglyphs")
            is_suspicious = True

        # 4. Decode URL percent-encoding
        current, reps_url = decode_url_encoding(current)
        if reps_url and "url_encoding" not in transformations:
            transformations.append("url_encoding")
            is_suspicious = True

        # 5. Decode Base64 recursively
        current, reps_b64, depth = decode_base64_recursive(current, max_depth=3)
        if reps_b64:
            if "base64" not in transformations:
                transformations.append("base64")
            if depth > 1 and "base64_recursive" not in transformations:
                transformations.append("base64_recursive")
            is_suspicious = True

        # 6. Decode Hex
        current, reps_hex = decode_hex(current)
        if reps_hex and "hex" not in transformations:
            transformations.append("hex")
            is_suspicious = True

        # 7. Detect ROT13
        is_rot, rot_text = detect_rot13(current)
        if is_rot and "rot13" not in transformations:
            current = rot_text
            transformations.append("rot13")
            is_suspicious = True

        if current == prev:
            break

    return DecodedResult(
        original=text,
        decoded=current,
        transformations=transformations,
        is_suspicious=is_suspicious,
    )
