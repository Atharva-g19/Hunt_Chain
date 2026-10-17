# Contributing to Hunt_Chain

Thank you for your interest in contributing to **Hunt_Chain**! Whether you are adding a new vulnerability tester family, optimizing reconnaissance providers, fixing cross-platform compatibility, or improving report generation, your contributions are welcome.

Please review this guide before submitting issues or pull requests.

---

## Code of Conduct

By participating in this project, you agree to uphold our [Code of Conduct](CODE_OF_CONDUCT.md). Please treat all community members with respect and professionalism.

---

## Development Setup

Hunt_Chain is built with Python 3.11+ and is tested across **Linux**, **macOS**, and **Windows**.

### 1. Clone the Repository
```bash
git clone https://github.com/Atharva-g19/Hunt_Chain.git
cd Hunt_Chain
```

### 2. Create a Virtual Environment
```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows (PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install in Editable Mode
```bash
pip install --upgrade pip setuptools wheel
pip install pytest pytest-cov pyyaml rich requests pydantic urllib3 jsonschema dnspython

# Install all subpackages in editable mode
pip install -e "Project 1/ScopeGuard"
pip install -e "Project 2"
pip install -e "Project_3_Vulnerability"
pip install -e "Project_4_Validation_Exploitation"
pip install -e "Project_5_Reporting"
pip install -e .
```

---

## Running the Test Suites

Before submitting any pull request, ensure all test suites pass cleanly across all modules:

```bash
# 1. Project 1 - ScopeGuard (304 tests)
python -m pytest "Project 1/ScopeGuard/tests" -q

# 2. Project 2 - Reconnaissance Engine (470 tests)
python -m pytest "Project 2/tests" -q

# 3. Project 3 - Vulnerability Toolkit (22 Families)
python -m pytest "Project_3_Vulnerability/tests" -q

# 4. Project 4 - Validation & Controlled Exploitation (105 tests)
python -m pytest "Project_4_Validation_Exploitation/tests" -q

# 5. Project 5 - Findings & Reporting Manager (17 tests)
python -m pytest "Project_5_Reporting/tests" -q

# 6. Core Orchestrator Integration Tests (44 tests)
python -m pytest tests_hunt_chain -q

# 7. Ground-Truth Regression Harness (55 tests)
python -m pytest tests -q
```

---

## Architecture Guidelines

### Adding or Enhancing a Vulnerability Tester (Stage 3)
All vulnerability testers reside in `Project_3_Vulnerability/src/hunt_chain_vulnerability/testers/families/` and must adhere to the standardized family contract:
1. **Inherit from `VulnerabilityTester`**: Define a declarative `DefinitionV1` metadata block containing `test_id`, `name`, `vulnerability_family`, `prerequisites`, `allowed_methods`, and `safety_constraints`.
2. **Dynamic Surface Discovery**: Use `discover_injection_points()` or parameter parsing rather than hardcoded parameter names.
3. **Synthesize Validation Plans**: When a potential vulnerability is flagged, attach a structured `validation_plan` (`ValidationPlan` with mutation request and expectation criteria) so Stage 4 can independently verify it.
4. **Safety & Bounds**: Never execute destructive actions (no `DROP TABLE`, no arbitrary file deletions, no infinite fuzz loops).

### Cross-Platform Rules
- **Paths**: Never concatenate paths with string slashes (`/` or `\\`). Always use Python's `pathlib.Path` or `os.path`.
- **File Encodings**: Always specify `encoding="utf-8"` when reading or writing text files (`open(..., encoding="utf-8")`).
- **External Tools**: Check tool availability gracefully using `shutil.which()`. Do not assume external binary availability (e.g. `nmap`, `curl`, `notepad`).

---

## Pull Request Process

1. **Fork & Branch**: Create a feature branch with a descriptive name:
   ```bash
   git checkout -b feature/add-graphql-tester
   ```
2. **Write Unit Tests**: Every bug fix or new feature must include accompanying unit or integration tests.
3. **Commit Messages**: Follow standard conventional commit format (`feat: ...`, `fix: ...`, `docs: ...`, `test: ...`).
4. **Verify CI**: Ensure all 9 GitHub Actions matrix jobs (`ubuntu-latest`, `macos-latest`, `windows-latest` across Python 3.11, 3.12, 3.13) pass on your branch.
5. **Open Pull Request**: Describe the problem solved, approach taken, and testing performed.
