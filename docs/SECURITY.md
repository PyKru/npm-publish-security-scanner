# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x.x   | ✅ Yes    |
| < 1.0   | ❌ No     |

## Reporting a Vulnerability

**Do NOT open a public GitHub Issue for security vulnerabilities.**

1. Email `security@yourorg.com` with subject: `[SECURITY] npm-publish-security-scanner`
2. Include: description, reproduction steps, potential impact, suggested fix
3. You will receive acknowledgment within **48 hours**
4. Critical fixes are released within **7 days** of confirmation

## Security Guarantees

This scanner provides **defense-in-depth**, not a complete guarantee. It:
- Detects known secret patterns via regex + entropy analysis
- Catches common sourcemap leaks
- Validates publish manifests

It does NOT replace: manual code review, SAST tools, or runtime monitoring.
