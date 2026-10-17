from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class FamilyMetadata:
    family: str
    display_name: str
    cwe_id: str
    cwe_name: str
    owasp_category: str
    owasp_api_category: str
    default_impact: str
    remediation: tuple[str, ...]

    @property
    def cwe_url(self) -> str:
        num = "".join(filter(str.isdigit, self.cwe_id))
        return f"https://cwe.mitre.org/data/definitions/{num}.html"


# Canonical 22 Families in Hunt_Chain
FAMILY_REGISTRY: dict[str, FamilyMetadata] = {
    "clickjacking": FamilyMetadata(
        family="clickjacking",
        display_name="Clickjacking (UI Redressing)",
        cwe_id="CWE-1021",
        cwe_name="Improper Restriction of Rendered UI Layers or Frames",
        owasp_category="A05:2021-Security Misconfiguration",
        owasp_api_category="N/A",
        default_impact="Allows an attacker to frame sensitive user interfaces within a malicious external site, tricking authenticated victims into executing unintended administrative or destructive actions.",
        remediation=(
            "Enforce a Content-Security-Policy (CSP) with 'frame-ancestors 'none'' (or 'frame-ancestors 'self'' if embedded frames are required).",
            "Set the 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' response header for legacy browser defense-in-depth.",
        ),
    ),
    "open_redirect": FamilyMetadata(
        family="open_redirect",
        display_name="Open URL Redirection",
        cwe_id="CWE-601",
        cwe_name="URL Redirection to Untrusted Site ('Open Redirect')",
        owasp_category="A01:2021-Broken Access Control",
        owasp_api_category="N/A",
        default_impact="Allows attackers to construct legitimate-looking links that redirect victims to external credential harvesting portals, phishing sites, or malware payloads.",
        remediation=(
            "Avoid accepting raw target URLs from user input; rely on relative path paths or pre-registered destination keys.",
            "If external redirects are necessary, enforce a strict server-side destination allowlist against authorized domain origins.",
            "Present an intermediate confirmation warning page if redirecting outside the application boundary.",
        ),
    ),
    "cors": FamilyMetadata(
        family="cors",
        display_name="Cross-Origin Resource Sharing (CORS) Misconfiguration",
        cwe_id="CWE-942",
        cwe_name="Permissive Cross-Domain Policy with Untrusted Domains",
        owasp_category="A05:2021-Security Misconfiguration",
        owasp_api_category="API7:2023-Server Side Request Forgery / Security Misconfiguration",
        default_impact="Permits arbitrary third-party origins to read authenticated responses, hijack user sessions, or exfiltrate private API data.",
        remediation=(
            "Never dynamically reflect the client 'Origin' header into 'Access-Control-Allow-Origin' alongside 'Access-Control-Allow-Credentials: true'.",
            "Maintain an explicit, server-side whitelist of authorized trusted domains permitted to make cross-origin authenticated requests.",
            "Avoid wildcard origins ('*') on sensitive endpoints returning private or user-specific data.",
        ),
    ),
    "ssrf": FamilyMetadata(
        family="ssrf",
        display_name="Server-Side Request Forgery (SSRF)",
        cwe_id="CWE-918",
        cwe_name="Server-Side Request Forgery (SSRF)",
        owasp_category="A10:2021-Server-Side Request Forgery (SSRF)",
        owasp_api_category="API7:2023-Server Side Request Forgery",
        default_impact="Allows attackers to coerce backend application servers into querying internal microservices, cloud metadata endpoints (e.g. 169.254.169.254), or local loopback interfaces.",
        remediation=(
            "Enforce strict URL schema (only http/https) and resolve DNS entries to verify IP addresses are not in private, loopback (127.0.0.0/8), or link-local (169.254.0.0/16) CIDR blocks.",
            "Deploy a dedicated egress proxy with network-level firewall rules blocking requests to internal metadata services and private subnets.",
            "Disable HTTP redirection following in outbound HTTP client libraries or validate intermediate redirect targets before requesting.",
        ),
    ),
    "sql_injection": FamilyMetadata(
        family="sql_injection",
        display_name="SQL Injection (SQLi)",
        cwe_id="CWE-89",
        cwe_name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        owasp_category="A03:2021-Injection",
        owasp_api_category="API8:2023-Security Misconfiguration",
        default_impact="Enables unauthorized database querying, administrative authentication bypass, sensitive tenant data exfiltration, or database modifications.",
        remediation=(
            "Use parameterized queries (prepared statements) or Object-Relational Mapping (ORM) query builders for all database interactions.",
            "Never concatenate raw or unescaped user input into dynamic SQL strings.",
            "Enforce least-privilege database user account permissions to restrict administrative commands.",
        ),
    ),
    "xss": FamilyMetadata(
        family="xss",
        display_name="Cross-Site Scripting (XSS)",
        cwe_id="CWE-79",
        cwe_name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        owasp_category="A03:2021-Injection",
        owasp_api_category="N/A",
        default_impact="Executes malicious JavaScript in victim browsers within the context of the vulnerable application, enabling session token theft, DOM manipulation, and credential harvesting.",
        remediation=(
            "Apply contextual output encoding (HTML, JavaScript, URL, CSS attribute encoding) to all untrusted data rendered into the DOM.",
            "Implement a robust Content Security Policy (CSP) restricting script execution and prohibiting 'unsafe-inline'.",
            "Store session identifiers with the 'HttpOnly', 'Secure', and 'SameSite=Lax/Strict' cookie flags.",
        ),
    ),
    "idor_bola": FamilyMetadata(
        family="idor_bola",
        display_name="Broken Object Level Authorization (BOLA / IDOR)",
        cwe_id="CWE-639",
        cwe_name="Authorization Bypass Through User-Controlled Key",
        owasp_category="A01:2021-Broken Access Control",
        owasp_api_category="API1:2023-Broken Object Level Authorization",
        default_impact="Allows authenticated users to access, modify, or delete sensitive objects (invoices, user records, documents) belonging to other tenants simply by tampering with record identifiers.",
        remediation=(
            "Enforce object-level authorization checks at the data layer for every request verifying that the authenticated caller owns or has explicit permission for the requested record ID.",
            "Utilize unpredictable, non-sequential identifiers (e.g. UUIDv4) in API endpoints to prevent sequential enumeration.",
        ),
    ),
    "inventory_management": FamilyMetadata(
        family="inventory_management",
        display_name="Improper Inventory Management (Shadow/Zombie APIs)",
        cwe_id="CWE-1059",
        cwe_name="Incomplete Documentation of API Capabilities",
        owasp_category="A05:2021-Security Misconfiguration",
        owasp_api_category="API9:2023-Improper Inventory Management",
        default_impact="Exposes deprecated, unpatched, or debug API routes (e.g., /v1, /beta, /debug, /swagger) containing unpatched vulnerabilities or weaker authentication gates.",
        remediation=(
            "Decommission and unroute unversioned, legacy, or internal debug endpoints from public ingress routers.",
            "Maintain an automated API documentation pipeline (OpenAPI/Swagger) synced with deployed routes.",
            "Enforce uniform authentication and rate-limiting gateways across all API versions.",
        ),
    ),
    "bopla": FamilyMetadata(
        family="bopla",
        display_name="Broken Object Property Level Authorization (BOPLA / Mass Assignment)",
        cwe_id="CWE-915",
        cwe_name="Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        owasp_category="A01:2021-Broken Access Control",
        owasp_api_category="API3:2023-Broken Object Property Level Authorization",
        default_impact="Enables attackers to inject unauthorized object properties (e.g. 'is_admin': true, 'role': 'superuser', 'discount_rate': 100) through payload tampering.",
        remediation=(
            "Implement strict Data Transfer Object (DTO) schema validation defining explicit writeable field allowlists.",
            "Avoid binding raw request JSON directly to database entity models.",
            "Enforce field-level access control on sensitive object properties during update operations.",
        ),
    ),
    "csrf": FamilyMetadata(
        family="csrf",
        display_name="Cross-Site Request Forgery (CSRF)",
        cwe_id="CWE-352",
        cwe_name="Cross-Site Request Forgery (CSRF)",
        owasp_category="A01:2021-Broken Access Control",
        owasp_api_category="N/A",
        default_impact="Tricks authenticated victims into making unwanted state-changing requests (password changes, profile updates, fund transfers) via third-party web pages.",
        remediation=(
            "Implement anti-CSRF challenge tokens (synchronizer token pattern or Double-Submit Cookie) on all state-altering endpoints.",
            "Enforce the 'SameSite=Lax' or 'SameSite=Strict' attribute on session cookies.",
            "Reject non-GET requests missing custom request headers (e.g., 'X-Requested-With' or 'Content-Type: application/json').",
        ),
    ),
    "authentication_bypass": FamilyMetadata(
        family="authentication_bypass",
        display_name="Authentication Bypass",
        cwe_id="CWE-287",
        cwe_name="Improper Authentication",
        owasp_category="A07:2021-Identification and Authentication Failures",
        owasp_api_category="API2:2023-Broken Authentication",
        default_impact="Allows unauthorized actors to bypass identity verification, access protected resources without credentials, or forge session tokens.",
        remediation=(
            "Enforce multi-factor authentication (MFA) and cryptographic session signing on all sensitive administrative and user accounts.",
            "Validate authentication tokens and cookies centrally on every protected request.",
            "Implement secure session invalidation on logout and password resets.",
        ),
    ),
    "function_authorization": FamilyMetadata(
        family="function_authorization",
        display_name="Broken Function Level Authorization (BFLA)",
        cwe_id="CWE-285",
        cwe_name="Improper Authorization",
        owasp_category="A01:2021-Broken Access Control",
        owasp_api_category="API5:2023-Broken Function Level Authorization",
        default_impact="Allows regular users to invoke administrative, staff, or privileged functions (e.g. /admin/users/delete, /api/export) by manipulating URL paths or HTTP verbs.",
        remediation=(
            "Implement role-based access control (RBAC) or attribute-based access control (ABAC) decorators on all privileged controller actions.",
            "Deny administrative access by default, granting privileges only to verified administrative roles.",
            "Avoid relying solely on hidden UI elements to conceal privileged API endpoints.",
        ),
    ),
    "business_logic": FamilyMetadata(
        family="business_logic",
        display_name="Business Logic Vulnerability",
        cwe_id="CWE-840",
        cwe_name="Business Logic Errors",
        owasp_category="A04:2021-Insecure Design",
        owasp_api_category="API6:2023-Unrestricted Access to Sensitive Business Flows",
        default_impact="Circumvents application workflows, resulting in unauthorized discount applications, negative price purchases, coupon reuse, or skipping validation phases.",
        remediation=(
            "Enforce strict server-side state machine verification across multi-step checkout and registration workflows.",
            "Validate numerical parameters against realistic non-negative constraints on the backend.",
            "Ensure business rules are evaluated atomically within transactional boundaries.",
        ),
    ),
    "ato": FamilyMetadata(
        family="ato",
        display_name="Account Takeover (ATO) / Weak Authentication Recovery",
        cwe_id="CWE-640",
        cwe_name="Weak Password Recovery Mechanism for Forgotten Password",
        owasp_category="A07:2021-Identification and Authentication Failures",
        owasp_api_category="API2:2023-Broken Authentication",
        default_impact="Allows malicious actors to hijack user accounts via predictable reset tokens, password reset poisoning, or lack of rate limits on verification codes.",
        remediation=(
            "Generate cryptographically secure, high-entropy password reset tokens with a strict expiration window (15 minutes).",
            "Tie reset tokens to user state so that changing a password invalidates all existing tokens and sessions.",
            "Enforce strict IP and account-level rate limiting on login, registration, and reset request endpoints.",
        ),
    ),
    "security_misconfiguration": FamilyMetadata(
        family="security_misconfiguration",
        display_name="Security Misconfiguration",
        cwe_id="CWE-16",
        cwe_name="Configuration",
        owasp_category="A05:2021-Security Misconfiguration",
        owasp_api_category="API8:2023-Security Misconfiguration",
        default_impact="Reveals server runtime versions, enables insecure HTTP methods (e.g. TRACE/TRACK), leaves default credentials enabled, or disables transport layer security.",
        remediation=(
            "Harden server headers by removing 'Server', 'X-Powered-By', and runtime banner identifiers.",
            "Disable unnecessary HTTP methods (TRACE, TRACK, OPTIONS, WebDAV) on public web proxies.",
            "Enforce automated configuration management audits and benchmark against CIS security guidelines.",
        ),
    ),
    "rce": FamilyMetadata(
        family="rce",
        display_name="Remote Code Execution / OS Command Injection",
        cwe_id="CWE-78",
        cwe_name="Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        owasp_category="A03:2021-Injection",
        owasp_api_category="API8:2023-Security Misconfiguration",
        default_impact="Permits arbitrary operating system command execution on the host server, leading to complete server compromise, lateral network movement, and persistent backdoors.",
        remediation=(
            "Never invoke shell execution primitives (e.g. system, exec, popen, shell=True) with untrusted user input.",
            "Use language-native API libraries (e.g. image processing, cryptography, file system operations) rather than external shell commands.",
            "Enforce strict argument allowlisting and execution inside isolated, unprivileged container sandboxes.",
        ),
    ),
    "path_traversal_upload": FamilyMetadata(
        family="path_traversal_upload",
        display_name="Path Traversal & Arbitrary File Upload",
        cwe_id="CWE-22",
        cwe_name="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        owasp_category="A01:2021-Broken Access Control",
        owasp_api_category="N/A",
        default_impact="Allows attackers to traverse directory boundaries to read sensitive system configuration files (/etc/passwd) or upload executable server-side scripts (web shells).",
        remediation=(
            "Sanitize filenames using basename extraction and verify canonical resolved paths reside strictly within the intended storage directory.",
            "Store uploaded assets on separate static storage domains (e.g. S3 buckets) with execution permissions disabled.",
            "Validate file contents against MIME type magic bytes rather than user-supplied extensions.",
        ),
    ),
    "sensitive_disclosure": FamilyMetadata(
        family="sensitive_disclosure",
        display_name="Information Disclosure / Sensitive Data Exposure",
        cwe_id="CWE-200",
        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
        owasp_category="A01:2021-Broken Access Control",
        owasp_api_category="API3:2023-Broken Object Property Level Authorization",
        default_impact="Leaks sensitive API keys, cloud tokens, database connection strings, PII, internal IP structures, or debug stack traces to unauthorized consumers.",
        remediation=(
            "Strip source maps, debug logs, internal endpoints, and API secret keys from production client-side JavaScript bundles.",
            "Enforce generic error handling in production preventing detailed stack traces or database exception dumps.",
            "Apply automated secret scanning in CI/CD build pipelines.",
        ),
    ),
    "resource_consumption": FamilyMetadata(
        family="resource_consumption",
        display_name="Unrestricted Resource Consumption / Rate Limit Bypass",
        cwe_id="CWE-770",
        cwe_name="Allocation of Resources Without Limits or Throttling",
        owasp_category="A04:2021-Insecure Design",
        owasp_api_category="API4:2023-Unrestricted Resource Consumption",
        default_impact="Enables Denial-of-Service (DoS) attacks, brute-force credential stuffing, SMS toll fraud, or excessive memory/CPU exhaustion.",
        remediation=(
            "Enforce distributed rate limiting using token bucket algorithms at ingress API gateways.",
            "Limit request body payloads, upload file sizes, pagination page sizes, and execution timeouts.",
            "Protect authentication, recovery, and contact forms with CAPTCHA and progressive delays.",
        ),
    ),
    "subdomain_takeover": FamilyMetadata(
        family="subdomain_takeover",
        display_name="Subdomain Takeover",
        cwe_id="CWE-1051",
        cwe_name="Initialization with Untrusted Pointer Dereference (Dangling DNS Record)",
        owasp_category="A05:2021-Security Misconfiguration",
        owasp_api_category="N/A",
        default_impact="Allows attackers to claim abandoned third-party cloud hosting resources (AWS S3, GitHub Pages, Azure, Heroku) pointed to by organization DNS records, inheriting trust and cookies.",
        remediation=(
            "Audit DNS CNAME records and immediately remove dangling entries pointing to decommissioned external providers.",
            "Verify cloud asset ownership before pointing DNS records to external provider targets.",
            "Automate DNS continuous monitoring to detect orphaned records.",
        ),
    ),
    "third_party_api": FamilyMetadata(
        family="third_party_api",
        display_name="Unsafe Third-Party API Consumption",
        cwe_id="CWE-1385",
        cwe_name="Missing Origin or Path Verification in API Consumption",
        owasp_category="A08:2021-Software and Data Integrity Failures",
        owasp_api_category="API10:2023-Unsafe Consumption of APIs",
        default_impact="Blindly trusts third-party service responses, enabling downstream injection vulnerabilities, web hook forgery, or credential leakage to upstream partners.",
        remediation=(
            "Enforce strict schema validation and output sanitization on all responses received from third-party vendor APIs.",
            "Verify cryptographic HMAC signatures on inbound third-party webhooks.",
            "Enforce TLS verification and explicit timeout constraints when communicating with upstream providers.",
        ),
    ),
    "xxe": FamilyMetadata(
        family="xxe",
        display_name="XML External Entity (XXE) Injection",
        cwe_id="CWE-611",
        cwe_name="Improper Restriction of XML External Entity Reference",
        owasp_category="A05:2021-Security Misconfiguration",
        owasp_api_category="API8:2023-Security Misconfiguration",
        default_impact="Forces server XML parsers to resolve external entities, leading to arbitrary server file disclosure (/etc/passwd), internal port scanning, or Denial of Service (Billion Laughs).",
        remediation=(
            "Disable Document Type Definition (DTD) processing and external entity resolution (DOCTYPE / entity expansion) in all server-side XML parsers.",
            "Migrate API payload serialization from XML to JSON where possible.",
            "Update XML parser libraries to modern, secure defaults.",
        ),
    ),
}

# Alias mapping for alternate name representations in findings
ALIASES: dict[str, str] = {
    "information_disclosure": "sensitive_disclosure",
    "bfla": "function_authorization",
    "sqli": "sql_injection",
    "bola": "idor_bola",
    "idor": "idor_bola",
    "mass_assignment": "bopla",
}


def get_family_metadata(family_name: str) -> FamilyMetadata:
    """Retrieve canonical metadata for a vulnerability family."""
    normalized = family_name.lower().strip()
    resolved = ALIASES.get(normalized, normalized)
    if resolved in FAMILY_REGISTRY:
        return FAMILY_REGISTRY[resolved]

    # Graceful fallback for unexpected families
    return FamilyMetadata(
        family=family_name,
        display_name=family_name.replace("_", " ").title(),
        cwe_id="CWE-200",
        cwe_name="Information Exposure",
        owasp_category="A05:2021-Security Misconfiguration",
        owasp_api_category="API8:2023-Security Misconfiguration",
        default_impact="May allow unauthorized access or security policy circumvention.",
        remediation=(
            "Apply least-privilege security controls and input validation.",
            "Audit application configuration against industry best practices.",
        ),
    )
