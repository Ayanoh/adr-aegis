"""Unit tests for vinci_adr.sensor.decoders module."""

from vinci_adr.sensor.decoders import (
    DecodedResult,
    decode_all,
    decode_base64,
    decode_hex,
    decode_rot13,
    decode_url_encoding,
    detect_rot13,
    normalize_homoglyphs,
    normalize_unicode,
    remove_invisible_chars,
)


def test_remove_invisible_chars_basic() -> None:
    """Verify removal of zero-width and invisible formatting characters."""
    text_with_invisibles = "c\u200ba\u200bt /etc/shadow"
    cleaned, modified = remove_invisible_chars(text_with_invisibles)
    assert modified is True
    assert cleaned == "cat /etc/shadow"


def test_remove_invisible_chars_no_change() -> None:
    """Verify that clean text is not modified."""
    clean_text = "cat /etc/passwd"
    cleaned, modified = remove_invisible_chars(clean_text)
    assert modified is False
    assert cleaned == clean_text


def test_normalize_unicode_fullwidth() -> None:
    """Verify normalization of full-width Unicode homoglyphs."""
    fullwidth_text = "Ｉｇｎｏｒｅ"
    normalized, modified = normalize_unicode(fullwidth_text)
    assert modified is True
    assert normalized == "Ignore"


def test_normalize_unicode_no_change() -> None:
    """Verify that standard ASCII text remains unchanged."""
    ascii_text = "Standard English instruction."
    normalized, modified = normalize_unicode(ascii_text)
    assert modified is False
    assert normalized == ascii_text


def test_decode_base64_simple() -> None:
    """Verify decoding of a standalone Base64 encoded command."""
    b64_str = "Y3VybA=="  # Base64 for 'curl'
    decoded_text, replacements = decode_base64(b64_str)
    assert decoded_text == "curl"
    assert len(replacements) == 1
    assert replacements[0] == ("Y3VybA==", "curl")


def test_decode_base64_in_context() -> None:
    """Verify that only the Base64 portion in a mixed sentence is replaced."""
    mixed_text = "Please execute Y3VybA== on the server"
    decoded_text, replacements = decode_base64(mixed_text)
    assert decoded_text == "Please execute curl on the server"
    assert len(replacements) == 1
    assert replacements[0] == ("Y3VybA==", "curl")


def test_decode_base64_invalid() -> None:
    """Verify that invalid or binary Base64 strings are left unchanged."""
    invalid_text = "This is simply normal text with no valid base64."
    decoded_text, replacements = decode_base64(invalid_text)
    assert decoded_text == invalid_text
    assert replacements == []


def test_decode_hex_simple() -> None:
    """Verify decoding of a raw hex string."""
    hex_str = "726d202d7266"  # Hex for 'rm -rf'
    decoded_text, replacements = decode_hex(hex_str)
    assert decoded_text == "rm -rf"
    assert len(replacements) == 1
    assert replacements[0] == ("726d202d7266", "rm -rf")


def test_decode_hex_with_prefix() -> None:
    """Verify decoding of a hex string with a 0x prefix."""
    hex_with_prefix = "0x726d202d7266"
    decoded_text, replacements = decode_hex(hex_with_prefix)
    assert decoded_text == "rm -rf"
    assert len(replacements) == 1
    assert replacements[0] == ("0x726d202d7266", "rm -rf")


def test_decode_rot13() -> None:
    """Verify basic ROT13 translation."""
    rot13_str = "phey"  # ROT13 for 'curl'
    decoded_str = decode_rot13(rot13_str)
    assert decoded_str == "curl"


def test_detect_rot13_suspicious() -> None:
    """Verify detection of suspicious ROT13 encoded content."""
    # ROT13 of "curl http://evil.com"
    rot13_sentence = "phey uggc://rivy.pbz"
    is_suspicious, decoded_result = detect_rot13(rot13_sentence)
    assert is_suspicious is True
    assert "curl" in decoded_result


def test_decode_all_combined() -> None:
    """Verify decode_all pipeline on mixed invisible characters and Base64."""
    obfuscated_input = "c\u200ba\u200bt Y3VybA=="
    result = decode_all(obfuscated_input)
    assert isinstance(result, DecodedResult)
    assert result.decoded == "cat curl"
    assert result.is_suspicious is True
    assert "remove_invisible_chars" in result.transformations
    assert "base64" in result.transformations


def test_decode_all_clean() -> None:
    """Verify decode_all on clean input returns is_suspicious=False."""
    clean_input = "ls -la /home/user"
    result = decode_all(clean_input)
    assert isinstance(result, DecodedResult)
    assert result.decoded == clean_input
    assert result.is_suspicious is False
    assert result.transformations == []


# Tests Base64 Récursif
def test_decode_base64_nested() -> None:
    """Base64 dans Base64 doit être décodé."""
    # "curl" -> "Y3VybA==" -> "WTNWeWJBPT0="
    nested = "WTNWeWJBPT0="
    result = decode_all(nested)
    assert "curl" in result.decoded
    assert result.is_suspicious is True


def test_decode_base64_triple_nested() -> None:
    """Triple imbrication doit être détectée."""
    # 3 niveaux de Base64
    triple = "V1ROV2VXSkJQVDA9"  # Base64(Base64(Base64("curl")))
    result = decode_all(triple)
    assert "curl" in result.decoded
    assert result.is_suspicious is True


# Tests Homoglyphes
def test_normalize_homoglyphs_cyrillic() -> None:
    """Homoglyphes cyrilliques doivent être normalisés."""
    # "exec" écrit avec 'е' et 'с' cyrilliques
    cyrillic_exec = "ехес"  # е=U+0435, с=U+0441
    normalized, modified = normalize_homoglyphs(cyrillic_exec)
    assert normalized == "exec"
    assert modified is True


def test_normalize_homoglyphs_mixed() -> None:
    """Mix latin/cyrillique doit être normalisé."""
    mixed = "раssword"  # 'р' et 'а' cyrilliques
    normalized, modified = normalize_homoglyphs(mixed)
    assert normalized == "password"
    assert modified is True


# Tests URL Encoding
def test_decode_url_encoding_simple() -> None:
    """URL encoding simple doit être décodé."""
    encoded = "%63%75%72%6C"  # curl
    decoded, replacements = decode_url_encoding(encoded)
    assert decoded == "curl"
    assert len(replacements) > 0


def test_decode_url_encoding_partial() -> None:
    """URL encoding partiel doit être géré."""
    partial = "curl%20http%3A//evil.com"
    decoded, replacements = decode_url_encoding(partial)
    assert decoded == "curl http://evil.com"
    assert len(replacements) > 0


# Test Pipeline Complet
def test_decode_all_multi_layer_evasion() -> None:
    """Évasion multi-couches doit être détectée."""
    # Invisible chars + homoglyphes + Base64
    multi = "с\u200bаt WTNWeWJBPT0="  # "cat" avec cyrillique + nested base64
    result = decode_all(multi)
    assert "cat" in result.decoded
    assert "curl" in result.decoded
    assert result.is_suspicious is True
