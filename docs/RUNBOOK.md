# Incident Response Runbook

## 🚨 Scenario 1: Secret Published to npm

### Immediate Actions (< 15 minutes)
1. **Revoke the compromised credential immediately** — do not wait
   - AWS: IAM Console → Deactivate Access Key
   - GitHub: Settings → Developer Settings → Delete token
   - npm: `npm token revoke <token-id>`
2. **Unpublish the affected version**
   ```bash
   npm unpublish <package>@<version>  # only works within 72 hours
   ```
3. **Deprecate if unpublish window has passed**
   ```bash
   npm deprecate <package>@<version> "SECURITY: Contains leaked credentials — do not use"
   ```
4. **Audit who downloaded the compromised version**
   - Check npm download stats for the version
   - Notify downstream consumers via GitHub Advisory

### Follow-up Actions (< 24 hours)
5. Add the leaked pattern to `rules/custom-patterns.json`
6. Run full audit: `npm run scan`
7. Rotate ALL secrets that shared the same scope/environment
8. File a GitHub Security Advisory

---

## 🚨 Scenario 2: Sourcemap Leak in Published Package

1. Identify the affected version via npm pack
2. Check if proprietary source code is exposed in the map
3. Unpublish/deprecate the version
4. Add `.map` to `.npmignore` and `ALLOWED_MAP_FILES` env var if needed
5. Rebuild without source maps: set `sourceMap: false` in your bundler config
6. Re-publish the clean version

---

## 🚨 Scenario 3: CI/CD Secret Exposed in Workflow Logs

*(Referencing the tj-actions/changed-files supply chain attack, March 2025)*

1. **Immediately rotate ALL secrets** used during the affected time window
2. Review workflow logs for base64-encoded payloads
3. Pin all third-party Actions to commit SHAs:
   ```yaml
   uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
   ```
4. Enable GitHub's "Allow only selected actions" in repo Settings → Actions
5. Review OIDC token permissions — use `id-token: write` only when publishing

---

## Prevention Checklist

- [ ] All secrets stored in GitHub Actions Secrets, never in code
- [ ] Third-party Actions pinned to commit SHAs
- [ ] `GITHUB_TOKEN` permissions set to minimum required
- [ ] Branch protection enabled on `main`/`master`
- [ ] Required status checks include `security-scan` job
- [ ] npm trusted publishing (OIDC) configured — no long-lived `NPM_TOKEN`
- [ ] Nightly audit workflow enabled
- [ ] `.npmignore` reviewed quarterly
- 