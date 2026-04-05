# npm Publish Security Scanner

Prevent accidental npm publishes that expose source maps, hardcoded secrets, oversized packages, and unintended files before they leave your repository [1][2]. This project works as both a local scanner and a reusable GitHub Action so teams can enforce the same security checks in developer workflows and CI pipelines [1][3].

## What it does

This scanner runs four core checks before publish: sourcemap leak detection, secret scanning, unintended file detection, and dependency risk checks, then writes a consolidated `npm-security-report.json` result that can be used as a CI gate [2]. The GitHub Action version wraps the same logic into a composite action with configurable inputs like Node version, install command, build command, audit threshold, package size thresholds, working directory, and report artifact upload [1].

## What it catches

| Risk | What is checked |
|---|---|
| Source map leaks | `.map` files in build output or npm tarball, inline sourcemaps in JS/CSS, and local `sourceMappingURL` references [4] |
| Hardcoded secrets | Common tokens, private keys, JWT-like strings, high-entropy strings, and custom company-specific patterns from `rules/custom-patterns.json` [5] |
| Unintended publish files | `.env` files, keys/certs, CI leftovers, tests, oversized files, and risky tarball content based on `npm pack --dry-run --json` [6] |
| Dependency risk | `npm audit`, missing lockfiles, typosquatted package names, dev-only tools in production dependencies, and unpinned dependency warnings [7] |

## Repo layout

This repository is organized so beginners can understand where each piece belongs [3][1]. The key paths are:

```text
.github/
  actions/
    npm-publish-security-scan/
      action.yml
  workflows/
    npm-publish-security.yml
    scheduled-audit.yml
scripts/
  run-all-scans.js
  scan-sourcemaps.js
  scan-secrets.js
  scan-unintended-files.js
  scan-dependencies.js
rules/
  allowlist.json
  custom-patterns.json
tests/
  *.test.js
package.json
README.md
```

## Installation

Clone the repository and install dependencies locally before trying the scanner in CI [3]. The project expects Node 18+ and npm 9+ based on the `engines` declaration in `package.json` [3].

```bash
git clone https://github.com/PyKru/npm-publish-security-scanner.git
cd npm-publish-security-scanner
npm install
```

## Run locally

Use the local scripts first so you can see findings before wiring them into GitHub Actions [3]. The main entrypoint is `npm run scan`, and individual scanners are also exposed as separate npm scripts [3].

```bash
npm run scan
npm run scan:sourcemaps
npm run scan:secrets
npm run scan:files
npm run scan:deps
```

After each run, the scanner writes `npm-security-report.json`, which contains an overall `PASS` or `FAIL` result and per-scanner status data [2].

## GitHub Action usage

The repository ships a reusable composite action at `.github/actions/npm-publish-security-scan/action.yml`, so a consuming repo can call it directly in a workflow job [1]. The action sets up Node, validates the project files, optionally builds the package, runs the scans, exposes outputs, and uploads the JSON report as an artifact when enabled [1].

### Minimal workflow

Use this in another repository to run the scanner on every pull request [1].

```yaml
name: npm security scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run npm publish security scan
        id: security
        uses: PyKru/npm-publish-security-scanner/.github/actions/npm-publish-security-scan@main
        with:
          node-version: '20'
          install-command: 'npm ci --ignore-scripts'
          build-command: 'npm run build --if-present'
          audit-level: 'high'
          allowed-map-files: ''
          max-file-mb: '5'
          max-total-mb: '50'
          upload-artifact: 'true'

      - name: Fail on scan failure
        if: ${{ steps.security.outputs.overall != 'PASS' }}
        run: |
          echo "Security scan failed"
          exit 1
```

## Action inputs

These are the main action inputs exposed by `action.yml` [1].

| Input | Default | Purpose |
|---|---:|---|
| `node-version` | `20` | Node.js version used during the scan [1] |
| `install-command` | `npm ci --ignore-scripts` | Safe dependency installation command [1] |
| `build-command` | `npm run build --if-present` | Build command before scanning publish output [1] |
| `audit-level` | `high` | Threshold passed to dependency scanning logic [1] |
| `allowed-map-files` | `''` | Comma-separated map filenames to permit [1] |
| `max-file-mb` | `5` | Maximum single file size in the tarball [1] |
| `max-total-mb` | `50` | Maximum total tarball size [1] |
| `working-directory` | `.` | Package directory for monorepos or subprojects [1] |
| `upload-artifact` | `true` | Upload `npm-security-report.json` as an artifact [1] |

## Action outputs

The action exposes two outputs that are useful for downstream workflow logic [1].

| Output | Meaning |
|---|---|
| `overall` | `PASS` or `FAIL` result from the complete scan [1] |
| `report-file` | Path to the generated JSON report file [1] |

## Built-in workflows

The repo includes two starter workflows for teams that want ready-made CI instead of writing their own from scratch [8][9]. `npm-publish-security.yml` is the main security gate for pushes and manual publish requests, and `scheduled-audit.yml` is the recurring audit workflow for ongoing repository hygiene [8][9].

### Main security gate

The main workflow installs dependencies with `npm ci --ignore-scripts`, builds the project, runs the scanners, uploads the report artifact, and can optionally publish after a successful run [8]. It is meant to stop risky packages before they reach npm, though you should align it fully with trusted publishing if you adopt OIDC-based publishing [8].

### Scheduled audit

The scheduled workflow runs on a cron schedule and can open a GitHub issue when the nightly scan fails, which is useful for newly disclosed dependency vulnerabilities or changes in repo state that were not caught during active development [9]. This gives teams a second line of defense beyond pull requests and manual release runs [9].

## Policy files

The `rules` directory lets your team define explicit exceptions and organization-specific detections [10][5]. These files should be reviewed by security owners because they control what gets suppressed and what gets flagged [10][5].

### `rules/allowlist.json`

Use this file only for approved exceptions, and keep entries narrow, documented, and time-bound [10]. A typical allowlist entry includes the match value, reason, approver, and expiry date so policy exceptions do not become permanent blind spots [10].

Example:

```json
{
  "version": "1.1",
  "allowedMapFiles": ["bundle.js.map"],
  "allowedSecretPatterns": [
    {
      "pattern": "EXAMPLE_PLACEHOLDER_TOKEN",
      "path": "README.md",
      "reason": "Used only in docs",
      "approvedBy": "security-team",
      "expires": "2026-12-31"
    }
  ],
  "allowedFiles": []
}
```

### `rules/custom-patterns.json`

Use this file for internal token formats that public scanners would never know about, such as company API tokens or service account IDs [5]. This makes the scanner much more useful in real organizations because most sensitive credentials are often internal, not only third-party vendor keys [5].

Example:

```json
{
  "version": "1.0",
  "patterns": [
    {
      "name": "Company Internal API Token",
      "regex": "MYCO_[A-Z0-9]{32}",
      "severity": "HIGH",
      "description": "Internal API tokens for MYCO services"
    }
  ]
}
```

## Monorepo usage

If your package lives in a subdirectory, set `working-directory` in the action so the scanner looks at the correct `package.json`, scripts, and lockfile [1]. This makes the action usable in larger repos where the publishable package is not stored at the repository root [1].

```yaml
- name: Run security scan for package A
  uses: PyKru/npm-publish-security-scanner/.github/actions/npm-publish-security-scan@main
  with:
    working-directory: packages/package-a
    install-command: 'npm ci --ignore-scripts'
    build-command: 'npm run build --if-present'
```

## Beginner onboarding

If you are new to GitHub Actions, use this simple setup sequence:
1. Copy the repo or install it in a test repository.
2. Confirm `scripts/` and `rules/` exist in the target package [1].
3. Run `npm run scan` locally and review `npm-security-report.json` [3][2].
4. Add the minimal workflow shown above to `.github/workflows/npm-security-scan.yml`.
5. Open a pull request and verify the Action passes.
6. Add custom patterns and allowlist entries only after the baseline scan works [10][5].

A good beginner exercise is to create a fake `.env` file or a fake `.map` file in `dist/` and confirm the workflow fails, because that proves the control is actually protecting your repo and not just printing logs [6][4].

## Local development

The package defines npm scripts for scanning, testing, linting, and release, so contributors can use the same commands locally that CI relies on [3]. The tests should include policy-focused coverage so future refactors do not silently bypass allowlists or custom secret patterns [3].

Typical workflow:

```bash
npm install
npm run scan
npm test
```

## Security recommendations

For a stronger production rollout, pin third-party GitHub Actions to full commit SHAs rather than floating tags, because the current examples use version tags and SHA pinning provides stronger workflow supply-chain protection [8][9][1]. If you publish to npm, prefer a consistent trusted publishing setup rather than mixing OIDC claims with legacy token injection, because your publish workflow should match the security story you document for users [8].

## Troubleshooting

### `package.json not found`
The action validates that `package.json` exists in the selected `working-directory`, so confirm you set the correct path in monorepos [1].

### `scripts/run-all-scans.js not found`
The action requires the scanner scripts to be present in the target package because it calls them directly [1].

### `npm-security-report.json not found`
This usually means the scanner crashed before writing the report, so run the scripts locally and check syntax first [1][2].

### Build fails in CI
Use a safer or simpler `build-command`, or set it to `npm run build --if-present` so repos without a build step still work cleanly [1].

## Contributing

When contributing, keep changes small and testable, and update both docs and tests when scanner behavior changes because workflow behavior, allowlist logic, and secret-pattern matching are all policy-sensitive parts of the project [10][5][3]. If you change detection logic, add or update tests for allowlists, custom patterns, and report output to prevent regressions [10][5].

## License

Add your preferred open-source license in `LICENSE` and keep the README examples aligned with the exact files shipped in the repository, because beginners depend on copy-paste accuracy when onboarding [3].
