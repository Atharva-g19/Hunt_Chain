# Hunt_Chain Project 2 — Recon & Attack Surface Suite

Project 2 is the reconnaissance component of Hunt_Chain.

It takes an authorized target, discovers assets, analyzes DNS and infrastructure,
performs reconnaissance intelligence processing, builds an Attack Surface Model
v1, and produces machine-readable and human-readable output.

## Hunt_Chain Flow

Project 1 — ScopeGuard
        ↓
Authorization
        ↓
Project 2 — Recon & Attack Surface
        ↓
Project 3 — Vulnerability Testing
        ↓
Project 4 — Manual Testing
        ↓
Project 5 — Findings & Reporting

## V1 Features

- ScopeGuard authorization boundary
- Certificate Transparency discovery
- Asset normalization and deduplication
- DNS resolution and analysis
- Wildcard DNS detection
- Potential dangling CNAME indicators
- Response SHA-256 hashing
- Technology fingerprinting
- Infrastructure intelligence
- Shared-IP awareness
- Correlation
- Attack Surface Model v1
- JSON output
- Human-readable report
- Passive-only execution mode
- Politeness and rate limiting
- CLI interface

## V1 Exclusions

Project 2 does not perform:

- Vulnerability exploitation
- SQL injection testing
- XSS exploitation
- Authentication attacks
- Password attacks
- Nuclei scanning
- WAF bypass
- Aggressive brute force
- DNS takeover exploitation
- Full cloud enumeration

These belong to later Hunt_Chain projects or future versions.

## Configuration

Default configuration:

    config/default.yaml

The default ScopeGuard reference is intentionally a placeholder.
Reconnaissance will not execute until valid authorization is supplied.

## CLI

Show help:

    python -m hunt_chain_recon.cli.commands --help

Run with configuration:

    python -m hunt_chain_recon.cli.commands --config config/default.yaml

Override output directory:

    python -m hunt_chain_recon.cli.commands --config config/default.yaml --output ./output

## Output

Project 2 can generate:

    attack_surface.json
    recon_report.txt

## Testing

Run all tests:

    python -m pytest -v

Project 2 uses deterministic fixtures and mocks for testing and does not require
external websites for its core test suite.

## Status

Project 2 V1 implementation is complete pending final repository verification.