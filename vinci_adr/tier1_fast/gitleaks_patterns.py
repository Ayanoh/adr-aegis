"""Gitleaks patterns - auto-generated, do not edit manually.

Source: https://github.com/gitleaks/gitleaks
License: MIT
Generated: 2026-08-18 00:59:53Z
"""

import re

from vinci_adr.core.schema import ThreatSeverity

# (name, compiled_pattern, min_entropy, severity)
GITLEAKS_PATTERNS: list[tuple[str, re.Pattern[str], float, ThreatSeverity]] = [
    (
        "1password-secret-key",
        re.compile(
            "\\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\\b"
        ),
        3.8,
        ThreatSeverity.HIGH,
    ),
    (
        "1password-service-account-token",
        re.compile("ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}"),
        4.0,
        ThreatSeverity.HIGH,
    ),
    (
        "adafruit-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:adafruit)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "adobe-client-id",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:adobe)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        2.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "age-secret-key",
        re.compile("AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "airtable-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:airtable)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{17})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.CRITICAL,
    ),
    (
        "airtable-personnal-access-token",
        re.compile("\\b(pat[a-zA-Z0-9]{14}\\.[a-f0-9]{64})\\b"),
        3.0,
        ThreatSeverity.CRITICAL,
    ),
    (
        "algolia-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:algolia)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "alibaba-secret-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:alibaba)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "anthropic-admin-api-key",
        re.compile("\\b(sk-ant-admin01-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    ("artifactory-api-key", re.compile("\\bAKCp[A-Za-z0-9]{69}\\b"), 4.5, ThreatSeverity.MEDIUM),
    (
        "artifactory-reference-token",
        re.compile("\\bcmVmd[A-Za-z0-9]{59}\\b"),
        4.5,
        ThreatSeverity.HIGH,
    ),
    (
        "asana-client-id",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "asana-client-secret",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "atlassian-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:(?-i:ATLASSIAN|[Aa]tlassian)|(?-i:CONFLUENCE|[Cc]onfluence)|(?-i:JIRA|[Jj]ira))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{20}[a-f0-9]{4})(?:[\\x60'\"\\s;]|\\\\[nr]|$)|\\b(ATATT3[A-Za-z0-9_\\-=]{186})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.5,
        ThreatSeverity.HIGH,
    ),
    (
        "aws-amazon-bedrock-api-key-long-lived",
        re.compile("\\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.CRITICAL,
    ),
    (
        "aws-amazon-bedrock-api-key-short-lived",
        re.compile("bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t"),
        3.0,
        ThreatSeverity.CRITICAL,
    ),
    (
        "azure-ad-client-secret",
        re.compile(
            "(?:^|[\\\\'\"\\x60\\s>=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\\\'\"\\x60\\s<),])"
        ),
        3.0,
        ThreatSeverity.CRITICAL,
    ),
    (
        "beamer-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:beamer)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(b_[a-z0-9=_\\-]{44})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "bitbucket-client-id",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "bitbucket-client-secret",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "bittrex-access-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "bittrex-secret-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "cisco-meraki-api-key",
        re.compile(
            "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:(?-i:[Mm]eraki|MERAKI))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "clickhouse-cloud-api-secret-key",
        re.compile("\\b(4b1d[A-Za-z0-9]{38})\\b"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    ("clojars-api-token", re.compile("(?i)CLOJARS_[a-z0-9]{60}"), 2.0, ThreatSeverity.HIGH),
    (
        "cloudflare-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        2.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "cloudflare-global-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{37})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        2.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "cloudflare-origin-ca-key",
        re.compile("\\b(v1\\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        2.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "codecov-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:codecov)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "cohere-api-token",
        re.compile(
            "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        4.0,
        ThreatSeverity.HIGH,
    ),
    (
        "coinbase-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:coinbase)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "confluent-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "confluent-secret-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "contentful-delivery-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:contentful)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{43})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "databricks-api-token",
        re.compile("\\b(dapi[a-f0-9]{32}(?:-\\d)?)(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "datadog-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:datadog)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "defined-networking-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:dnkey)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(dnkey-[a-z0-9=_\\-]{26}-[a-z0-9=_\\-]{52})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "digitalocean-access-token",
        re.compile("\\b(doo_v1_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "digitalocean-pat",
        re.compile("\\b(dop_v1_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "digitalocean-refresh-token",
        re.compile("(?i)\\b(dor_v1_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "discord-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "discord-client-id",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{18})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "discord-client-secret",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "droneci-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:droneci)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "dropbox-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{15})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "dropbox-long-lived-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\\-_=]{43})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "dropbox-short-lived-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(sl\\.[a-z0-9\\-=_]{135})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "etsy-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:(?-i:ETSY|[Ee]tsy))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "facebook-access-token",
        re.compile("(?i)\\b(\\d{15,16}(\\||%)[0-9a-z\\-_]{27,40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "facebook-secret",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:facebook)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "fastly-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:fastly)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "finicity-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "finicity-client-secret",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "finnhub-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:finnhub)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "flickr-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:flickr)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "flyio-access-token",
        re.compile(
            "\\b((?:fo1_[\\w-]{43}|fm1[ar]_[a-zA-Z0-9+\\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\\/]{100,}={0,3}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        4.0,
        ThreatSeverity.HIGH,
    ),
    (
        "freemius-secret-key",
        re.compile("(?i)[\"']secret_key[\"']\\s*=>\\s*[\"'](sk_[\\S]{29})[\"']"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "freshbooks-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:freshbooks)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "gcp-api-key",
        re.compile("\\b(AIza[\\w-]{35})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        4.0,
        ThreatSeverity.CRITICAL,
    ),
    ("github-app-token", re.compile("(?:ghu|ghs)_[0-9a-zA-Z]{36}"), 3.0, ThreatSeverity.HIGH),
    ("github-fine-grained-pat", re.compile("github_pat_\\w{82}"), 3.0, ThreatSeverity.HIGH),
    ("github-refresh-token", re.compile("ghr_[0-9a-zA-Z]{36}"), 3.0, ThreatSeverity.HIGH),
    (
        "gitlab-cicd-job-token",
        re.compile("glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    ("gitlab-deploy-token", re.compile("gldt-[0-9a-zA-Z_\\-]{20}"), 3.0, ThreatSeverity.HIGH),
    (
        "gitlab-feature-flag-client-token",
        re.compile("glffct-[0-9a-zA-Z_\\-]{20}"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    ("gitlab-feed-token", re.compile("glft-[0-9a-zA-Z_\\-]{20}"), 3.0, ThreatSeverity.HIGH),
    (
        "gitlab-incoming-mail-token",
        re.compile("glimt-[0-9a-zA-Z_\\-]{25}"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "gitlab-kubernetes-agent-token",
        re.compile("glagent-[0-9a-zA-Z_\\-]{50}"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    ("gitlab-oauth-app-secret", re.compile("gloas-[0-9a-zA-Z_\\-]{64}"), 3.0, ThreatSeverity.HIGH),
    ("gitlab-pat", re.compile("glpat-[\\w-]{20}"), 3.0, ThreatSeverity.HIGH),
    (
        "gitlab-pat-routable",
        re.compile("\\bglpat-[0-9a-zA-Z_-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b"),
        4.0,
        ThreatSeverity.HIGH,
    ),
    ("gitlab-ptt", re.compile("glptt-[0-9a-f]{40}"), 3.0, ThreatSeverity.HIGH),
    ("gitlab-rrt", re.compile("GR1348941[\\w-]{20}"), 3.0, ThreatSeverity.HIGH),
    (
        "gitlab-runner-authentication-token",
        re.compile("glrt-[0-9a-zA-Z_\\-]{20}"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "gitlab-runner-authentication-token-routable",
        re.compile("\\bglrt-t\\d_[0-9a-zA-Z_\\-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b"),
        4.0,
        ThreatSeverity.HIGH,
    ),
    ("gitlab-scim-token", re.compile("glsoat-[0-9a-zA-Z_\\-]{20}"), 3.0, ThreatSeverity.HIGH),
    (
        "gitlab-session-cookie",
        re.compile("_gitlab_session=[0-9a-z]{32}"),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "gitter-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:gitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "grafana-api-key",
        re.compile("(?i)\\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "grafana-cloud-api-token",
        re.compile("(?i)\\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "grafana-service-account-token",
        re.compile("(?i)\\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "harness-api-key",
        re.compile("(?:pat|sat)\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{20}"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "hashicorp-tf-api-token",
        re.compile("(?i)[a-z0-9]{14}\\.(?-i:atlasv1)\\.[a-z0-9\\-_=]{60,70}"),
        3.5,
        ThreatSeverity.HIGH,
    ),
    (
        "hashicorp-tf-password",
        re.compile(
            '(?i)[\\w.-]{0,50}?(?:administrator_login_password|password)(?:[ \\t\\w.-]{0,20})[\\s\'"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60\'"\\s=]{0,5}("[a-z0-9=_\\-]{8,20}")(?:[\\x60\'"\\s;]|\\\\[nr]|$)'
        ),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "heroku-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:heroku)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "heroku-api-key-v2",
        re.compile("\\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        4.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "hubspot-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:hubspot)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "huggingface-access-token",
        re.compile("\\b(hf_(?i:[a-z]{34}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "huggingface-organization-api-token",
        re.compile("\\b(api_org_(?i:[a-z]{34}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "infracost-api-token",
        re.compile("\\b(ico-[a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "intercom-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:intercom)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{60})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "jfrog-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{73})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "jfrog-identity-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "jwt",
        re.compile(
            "\\b(ey[a-zA-Z0-9]{17,}\\.ey[a-zA-Z0-9\\/\\\\_-]{17,}\\.(?:[a-zA-Z0-9\\/\\\\_-]{10,}={0,2})?)(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "jwt-base64",
        re.compile(
            "\\bZXlK(?:(?P<alg>aGJHY2lPaU)|(?P<apu>aGNIVWlPaU)|(?P<apv>aGNIWWlPaU)|(?P<aud>aGRXUWlPaU)|(?P<b64>aU5qUWlP)|(?P<crit>amNtbDBJanBi)|(?P<cty>amRIa2lPaU)|(?P<epk>bGNHc2lPbn)|(?P<enc>bGJtTWlPaU)|(?P<jku>cWEzVWlPaU)|(?P<jwk>cWQyc2lPb)|(?P<iss>cGMzTWlPaU)|(?P<iv>cGRpSTZJ)|(?P<kid>cmFXUWlP)|(?P<key_ops>clpYbGZiM0J6SWpwY)|(?P<kty>cmRIa2lPaUp)|(?P<nonce>dWIyNWpaU0k2)|(?P<p2c>d01tTWlP)|(?P<p2s>d01uTWlPaU)|(?P<ppt>d2NIUWlPaU)|(?P<sub>emRXSWlPaU)|(?P<svt>emRuUWlP)|(?P<tag>MFlXY2lPaU)|(?P<typ>MGVYQWlPaUp)|(?P<url>MWNtd2l)|(?P<use>MWMyVWlPaUp)|(?P<ver>MlpYSWlPaU)|(?P<version>MlpYSnphVzl1SWpv)|(?P<x>NElqb2)|(?P<x5c>NE5XTWlP)|(?P<x5t>NE5YUWlPaU)|(?P<x5ts256>NE5YUWpVekkxTmlJNkl)|(?P<x5u>NE5YVWlPaU)|(?P<zip>NmFYQWlPaU))[a-zA-Z0-9\\/\\\\_+\\-\\r\\n]{40,}={0,2}"
        ),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "kraken-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:kraken)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9\\/=_\\+\\-]{80,90})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "kubernetes-secret-yaml",
        re.compile(
            '(?i)(?:\\bkind:[ \\t]*["\']?\\bsecret\\b["\']?(?s:.){0,200}?\\bdata:(?s:.){0,100}?\\s+([\\w.-]+:(?:[ \\t]*(?:\\||>[-+]?)\\s+)?[ \\t]*(?:["\']?[a-z0-9+/]{10,}={0,3}["\']?|\\{\\{[ \\t\\w"|$:=,.-]+}}|""|\'\'))|\\bdata:(?s:.){0,100}?\\s+([\\w.-]+:(?:[ \\t]*(?:\\||>[-+]?)\\s+)?[ \\t]*(?:["\']?[a-z0-9+/]{10,}={0,3}["\']?|\\{\\{[ \\t\\w"|$:=,.-]+}}|""|\'\'))(?s:.){0,200}?\\bkind:[ \\t]*["\']?\\bsecret\\b["\']?)'
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "kucoin-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "kucoin-secret-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "launchdarkly-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:launchdarkly)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "linear-client-secret",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:linear)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "linkedin-client-id",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{14})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        2.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "linkedin-client-secret",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "lob-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((live|test)_[a-f0-9]{35})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "lob-pub-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((test|live)_pub_[a-f0-9]{31})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "looker-client-id",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "looker-client-secret",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "mailchimp-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:MailchimpSDK.initialize|mailchimp)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32}-us\\d\\d)(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "mailgun-private-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(key-[a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "mailgun-pub-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(pubkey-[a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "mailgun-signing-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "mapbox-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:mapbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(pk\\.[a-z0-9]{60}\\.[a-z0-9]{22})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "mattermost-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:mattermost)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{26})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "maxmind-license-key",
        re.compile("\\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        4.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "messagebird-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "messagebird-client-id",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "microsoft-teams-webhook",
        re.compile(
            "https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "netlify-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:netlify)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{40,46})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "new-relic-browser-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(NRJS-[a-f0-9]{19})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "new-relic-insert-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(NRII-[a-z0-9-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "new-relic-user-api-id",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "new-relic-user-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(NRAK-[a-z0-9]{27})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "notion-api-token",
        re.compile("\\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        4.0,
        ThreatSeverity.HIGH,
    ),
    (
        "npm-access-token",
        re.compile("(?i)\\b(npm_[a-z0-9]{36})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "nuget-config-password",
        re.compile('(?i)<add key=\\"(?:(?:ClearText)?Password)\\"\\s*value=\\"(.{8,})\\"\\s*/>'),
        1.0,
        ThreatSeverity.HIGH,
    ),
    (
        "nytimes-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:nytimes|new-york-times,|newyorktimes)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "octopus-deploy-api-key",
        re.compile("\\b(API-[A-Z0-9]{26})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "okta-access-token",
        re.compile(
            "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:(?-i:[Oo]kta|OKTA))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(00[\\w=\\-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        4.0,
        ThreatSeverity.HIGH,
    ),
    (
        "perplexity-api-key",
        re.compile("\\b(pplx-[a-zA-Z0-9]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$|\\b)"),
        4.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "plaid-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "plaid-client-id",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.5,
        ThreatSeverity.MEDIUM,
    ),
    (
        "plaid-secret-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.5,
        ThreatSeverity.HIGH,
    ),
    (
        "planetscale-oauth-token",
        re.compile("\\b(pscale_oauth_[\\w=\\.-]{32,64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.CRITICAL,
    ),
    (
        "prefect-api-token",
        re.compile("\\b(pnu_[a-zA-Z0-9]{36})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "private-key",
        re.compile(
            "(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\\s\\S-]{64,}?KEY(?: BLOCK)?-----"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "privateai-api-token",
        re.compile(
            "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:private[_-]?ai)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "pulumi-api-token",
        re.compile("\\b(pul-[a-f0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "pypi-upload-token",
        re.compile("pypi-AgEIcHlwaS5vcmc[\\w-]{50,1000}"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "rapidapi-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:rapidapi)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{50})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "readme-api-token",
        re.compile("\\b(rdme_[a-z0-9]{70})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "rubygems-api-token",
        re.compile("\\b(rubygems_[a-f0-9]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "scalingo-api-token",
        re.compile("\\b(tk-us-[\\w-]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "sendbird-access-id",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "sendbird-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "sentry-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:sentry)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "sentry-user-token",
        re.compile("\\b(sntryu_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.5,
        ThreatSeverity.HIGH,
    ),
    (
        "settlemint-application-access-token",
        re.compile("\\b(sm_aat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "settlemint-personal-access-token",
        re.compile("\\b(sm_pat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "settlemint-service-access-token",
        re.compile("\\b(sm_sat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "shippo-api-token",
        re.compile("\\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    ("shopify-access-token", re.compile("shpat_[a-fA-F0-9]{32}"), 2.0, ThreatSeverity.HIGH),
    ("shopify-custom-access-token", re.compile("shpca_[a-fA-F0-9]{32}"), 2.0, ThreatSeverity.HIGH),
    (
        "shopify-private-app-access-token",
        re.compile("shppa_[a-fA-F0-9]{32}"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    ("shopify-shared-secret", re.compile("shpss_[a-fA-F0-9]{32}"), 2.0, ThreatSeverity.HIGH),
    (
        "sidekiq-secret",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "sidekiq-sensitive-url",
        re.compile(
            "(?i)\\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\\/|\\#|\\?|:]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "slack-app-token",
        re.compile("(?i)xapp-\\d-[A-Z0-9]+-\\d+-[a-z0-9]+"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "slack-bot-token",
        re.compile("xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "slack-config-access-token",
        re.compile("(?i)xoxe.xox[bp]-\\d-[A-Z0-9]{163,166}"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "slack-config-refresh-token",
        re.compile("(?i)xoxe-\\d-[A-Z0-9]{146}"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "slack-legacy-bot-token",
        re.compile("xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "slack-legacy-token",
        re.compile("xox[os]-\\d+-\\d+-\\d+-[a-fA-F\\d]+"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "slack-legacy-workspace-token",
        re.compile("xox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "slack-user-token",
        re.compile("xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "slack-webhook-url",
        re.compile(
            "(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "snyk-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "sonar-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:sonar[_.-]?(login|token))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_\\-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "sourcegraph-access-token",
        re.compile(
            "(?i)\\b(\\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\\b)(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "square-access-token",
        re.compile("\\b((?:EAAA|sq0atp-)[\\w-]{22,60})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "squarespace-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:squarespace)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "stripe-access-token",
        re.compile(
            "\\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        2.0,
        ThreatSeverity.HIGH,
    ),
    (
        "sumologic-access-id",
        re.compile(
            "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(su[a-zA-Z0-9]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "sumologic-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "telegram-bot-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:telegr)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{5,16}:(?-i:A)[a-z0-9_\\-]{34})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "travisci-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:travis)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{22})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    ("twilio-api-key", re.compile("SK[0-9a-fA-F]{32}"), 3.0, ThreatSeverity.MEDIUM),
    (
        "twitch-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:twitch)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "twitter-access-secret",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{45})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "twitter-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "twitter-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "twitter-api-secret",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{50})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "twitter-bearer-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "typeform-api-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:typeform)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(tfp_[a-z0-9\\-_\\.=]{59})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "vault-batch-token",
        re.compile("\\b(hvb\\.[\\w-]{138,300})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"),
        4.0,
        ThreatSeverity.HIGH,
    ),
    (
        "vault-service-token",
        re.compile(
            "\\b((?:hvs\\.[\\w-]{90,120}|s\\.(?i:[a-z0-9]{24})))(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.5,
        ThreatSeverity.HIGH,
    ),
    (
        "yandex-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(t1\\.[A-Z0-9a-z_-]+[=]{0,2}\\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
    (
        "yandex-api-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(AQVN[A-Za-z0-9_\\-]{35,38})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.MEDIUM,
    ),
    (
        "yandex-aws-access-token",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(YC[a-zA-Z0-9_\\-]{38})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.CRITICAL,
    ),
    (
        "zendesk-secret-key",
        re.compile(
            "(?i)[\\w.-]{0,50}?(?:zendesk)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)"
        ),
        3.0,
        ThreatSeverity.HIGH,
    ),
]
