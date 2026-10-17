from __future__ import annotations

import re


class UnredactedSecretViolationError(RuntimeError):
    """Raised when an unredacted secret or sensitive credential is detected in report output."""
    pass


# High-confidence secret signatures that must NEVER appear in unredacted form in reports
STRICT_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("GitHub Personal Access Token", re.compile(r"\bghp_[0-9a-zA-Z]{36}\b")),
    ("GitHub Fine-Grained Token", re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{40,}\b")),
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Key Assignment", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b")),
    ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z]{8,}/B[0-9A-Za-z]{8,}/[0-9A-Za-z]{24,}")),
    ("Private Key Header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("High-Entropy API Secret Assignment", re.compile(r"(?i)(?:api_key|client_secret|auth_token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{24,}['\"]")),
]


def _luhn_checksum(card_num: str) -> bool:
    """Verify Luhn checksum for credit card strings."""
    digits = [int(c) for c in card_num if c.isdigit()]
    if len(digits) not in (13, 14, 15, 16, 17, 18, 19):
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def redact_string(val: str, prefix_len: int = 4, suffix_len: int = 4) -> str:
    """Redact a secret string preserving only edge characters."""
    clean = val.strip()
    if len(clean) <= (prefix_len + suffix_len):
        return "[REDACTED]"
    prefix = clean[:prefix_len]
    suffix = clean[-suffix_len:]
    stars = "*" * min(12, max(6, len(clean) - prefix_len - suffix_len))
    return f"{prefix}{stars}{suffix}"


def redact_text(text: str) -> str:
    """
    Apply automated redaction across text containing known secret/PII signatures.
    Leaves non-secret text intact.
    """
    if not text:
        return text

    redacted = text

    # Redact Stripe Live Keys
    redacted = re.sub(
        r"\bsk_live_([0-9a-zA-Z]{4})[0-9a-zA-Z]{16,}([0-9a-zA-Z]{4})\b",
        r"sk_live_\1********\2",
        redacted,
    )

    # Redact GitHub Tokens
    redacted = re.sub(
        r"\bghp_([0-9a-zA-Z]{4})[0-9a-zA-Z]{28}([0-9a-zA-Z]{4})\b",
        r"ghp_\1********\2",
        redacted,
    )

    # Redact AWS Access Keys
    redacted = re.sub(
        r"\bAKIA([0-9A-Z]{4})[0-9A-Z]{8}([0-9A-Z]{4})\b",
        r"AKIA\1********\2",
        redacted,
    )

    # Redact Google API Keys
    redacted = re.sub(
        r"\bAIza([0-9A-Za-z\-_]{4})[0-9A-Za-z\-_]{27}([0-9A-Za-z\-_]{4})\b",
        r"AIza\1********\2",
        redacted,
    )

    # Redact Slack Webhooks
    redacted = re.sub(
        r"https://hooks\.slack\.com/services/T[0-9A-Za-z]+/B[0-9A-Za-z]+/[0-9A-Za-z]+",
        "https://hooks.slack.com/services/[REDACTED_SLACK_WEBHOOK]",
        redacted,
    )

    # Redact Private Keys
    redacted = re.sub(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[^-]+-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY]\n-----END PRIVATE KEY-----",
        redacted,
        flags=re.DOTALL,
    )

    # Redact Credit Cards with Luhn validation
    potential_cards = re.findall(r"\b(?:\d{4}[-\s]?){3,4}\d{1,4}\b", redacted)
    for card in potential_cards:
        clean_digits = "".join(filter(str.isdigit, card))
        if _luhn_checksum(clean_digits):
            redacted_card = clean_digits[:4] + "********" + clean_digits[-4:]
            redacted = redacted.replace(card, redacted_card)

    return redacted


def scan_for_unredacted_secrets(text: str) -> list[str]:
    """
    Scan rendered report content for unredacted secret patterns.
    Returns a list of matched vulnerability/secret pattern names.
    """
    if not text:
        return []

    violations: list[str] = []
    for pattern_name, regex in STRICT_SECRET_PATTERNS:
        matches = regex.findall(text)
        if matches:
            violations.append(pattern_name)

    # Check for unredacted credit card numbers
    potential_cards = re.findall(r"\b(?:\d{4}[-\s]?){3,4}\d{1,4}\b", text)
    for card in potential_cards:
        clean_digits = "".join(filter(str.isdigit, card))
        if _luhn_checksum(clean_digits):
            violations.append("Credit Card Number (Luhn Validated)")
            break

    return violations


def assert_no_unredacted_secrets(content: str, destination_name: str = "report") -> None:
    """
    Pre-write safety gate.
    Scans content before writing to disk and FAILS LOUDLY if any unredacted secret is present.
    """
    violations = scan_for_unredacted_secrets(content)
    if violations:
        raise UnredactedSecretViolationError(
            f"Safety check failed: detected unredacted sensitive data in {destination_name}. "
            f"Violations found: {', '.join(violations)}. "
            f"Refusing to write report to prevent credential exposure."
        )
