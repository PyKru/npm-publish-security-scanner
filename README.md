# npm Publish Security Scanner

Protect your npm releases before they leave your repo.

This project is a security gate for JavaScript and TypeScript packages that catches **sourcemap leaks**, **hardcoded secrets**, **unintended published files**, and **dependency risks** before `npm publish`. It is built for local developer use, pull requests, CI pipelines, and reusable GitHub Actions integration.

## Why this repo exists

Publishing a package can accidentally expose far more than compiled code. Teams often leak `.map` files, `.env` files, `.npmrc` tokens, private keys, internal test fixtures, CI configs, or oversized artifacts because the publish tarball was never inspected directly.

This repository helps developers and CI/CD security teams:

- Stop accidental source exposure from `.map` files and inline sourcemaps.
- Detect secrets before they are committed, merged, or published.
- Inspect the **actual npm tarball** using `npm pack --dry-run --json`.
- Catch files that should never ship, such as `.env`, certs, test fixtures, CI files, and internal configs.
- Enforce dependency hygiene with `npm audit`, lockfile review, and typosquat checks.
- Standardize security gates across repositories with a reusable **GitHub Actions CI plugin**.
- Produce a machine-readable JSON report that security or platform teams can archive and review.

## What this repo helps with

### 1. Sourcemap leak prevention

The scanner blocks:

- `.map` files included in the publish tarball.
- Inline base64 sourcemaps embedded in JavaScript or CSS.
- Local `sourceMappingURL=` references that can expose internal source structure.

This matters because sourcemaps can reveal source code, comments, internal paths, package names, and implementation details that were never meant to be public.

### 2. Secret detection

The scanner looks for:

- AWS access keys and secret-style patterns.
- GitHub tokens, npm tokens, Stripe keys, Slack tokens, OpenAI keys, Google keys, JWTs.
- RSA, EC, and PGP private keys.
- `.env`-style file leaks.
- High-entropy strings that do not match known token patterns but still look sensitive.

### 3. Unintended publish files

The scanner detects sensitive or unwanted files such as:

- `.env*`, `.npmrc`, `.pem`, `.key`, `.p12`, `.crt`.
- `Dockerfile`, `docker-compose.yml`, `terraform.tfvars`, `.sentryclirc`.
- test files, fixtures, coverage output, CI configs, and local-only metadata.
- oversized files and bloated package output.

### 4. Dependency and supply chain checks

The scanner reviews:

- `npm audit` findings for known vulnerabilities.
- missing or weak lockfile protection.
- suspicious package names that resemble typosquatting.
- dev-only tools accidentally placed in production dependencies.
- unpinned production dependency versions.

## Features

- Local CLI scanner scripts.
- Full pre-publish orchestration.
- GitHub Actions workflows for PRs, scheduled audits, and publish gates.
- Reusable **composite action** CI plugin.
- JSON report output for automation.
- Security docs and runbook support.
- Team-friendly defaults with configurable thresholds.

## Repository structure

```text
npm-publish-security-scanner/
├── .github/
│   ├── actions/
│   │   └── npm-publish-security-scan/
│   │       └── action.yml
│   └── workflows/
│       ├── example-consumer-ci.yml
│       ├── npm-publish-security.yml
│       ├── pr-security-check.yml
│       └── scheduled-audit.yml
├── docs/
│   ├── RUNBOOK.md
│   └── SECURITY.md
├── rules/
│   ├── allowlist.json
│   └── custom-patterns.json
├── scripts/
│   ├── run-all-scans.js
│   ├── scan-dependencies.js
│   ├── scan-secrets.js
│   ├── scan-sourcemaps.js
│   └── scan-unintended-files.js
├── tests/
├── .npmignore
├── package.json
└── README.md
```

## Scanners included

### `scan-sourcemaps.js`
Detects `.map` files, inline sourcemaps, and suspicious local source map references.

### `scan-secrets.js`
Scans publishable files for hardcoded secrets, private keys, and high-entropy values.

### `scan-unintended-files.js`
Checks the tarball contents for files that should not be shipped and validates publish boundaries.

### `scan-dependencies.js`
Runs dependency risk checks such as `npm audit`, lockfile validation, typosquat detection, and dependency hygiene checks.

### `run-all-scans.js`
Runs all scanners together, prints a summary, and writes `npm-security-report.json`.

## Quick start

### Prerequisites

- Node.js 18+
- npm 9+
- A package repository with `package.json`

### Run locally

```bash
npm run scan
```

Run individual scanners:

```bash
npm run scan:sourcemaps
npm run scan:secrets
npm run scan:files
npm run scan:deps
```

## Typical developer workflow

### Before opening a PR

Run the scanner locally:

```bash
npm run scan
```

If the scanner fails:

1. Remove leaked files from the publish boundary.
2. Rotate any exposed credentials immediately.
3. Fix build settings that generate public sourcemaps.
4. Re-run the scan.

### Before publishing to npm

Use a `prepublishOnly` hook so a package cannot publish unless the checks pass:

```json
{
  "scripts": {
    "prepublishOnly": "npm run build && npm run scan"
  }
}
```

## CI plugin status

**Yes — a reusable CI plugin is implemented.**

It is provided as a GitHub Actions composite action here:

```text
.github/actions/npm-publish-security-scan/action.yml
```

GitHub supports composite actions for packaging reusable CI step logic, and reusable workflows for sharing larger workflow structures across repositories [1][2]. This repository uses a composite action so teams can insert one standard publish-security gate into many jobs and still pass inputs and read outputs in a simple way [1][3].

## CI plugin inputs

| Input | Default | Description |
|---|---|---|
| `node-version` | `20` | Node.js version used during the scan. |
| `install-command` | `npm ci --ignore-scripts` | Safe install command for CI. |
| `build-command` | `npm run build --if-present` | Build command executed before scans. |
| `audit-level` | `high` | Minimum npm audit severity threshold. |
| `allowed-map-files` | `''` | Comma-separated sourcemap allowlist. |
| `max-file-mb` | `5` | Maximum individual file size in MB. |
| `max-total-mb` | `50` | Maximum total package size in MB. |
| `upload-artifact` | `true` | Upload the JSON report artifact. |

## CI plugin outputs

| Output | Meaning |
|---|---|
| `overall` | `PASS` or `FAIL` |
| `report-file` | Path to the generated JSON report |

GitHub’s metadata syntax supports defined outputs for composite actions, which can be mapped from an internal step and then consumed by later workflow steps [3].

## Use the CI plugin in GitHub Actions

```yaml
name: npm Security Gate

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Run npm publish security plugin
        id: security
        uses: ./.github/actions/npm-publish-security-scan
        with:
          node-version: '20'
          install-command: 'npm ci --ignore-scripts'
          build-command: 'npm run build --if-present'
          audit-level: 'high'
          allowed-map-files: ''
          max-file-mb: '5'
          max-total-mb: '50'
          upload-artifact: 'true'

      - name: Read outputs
        run: |
          echo "Overall: ${{ steps.security.outputs.overall }}"
          echo "Report:  ${{ steps.security.outputs.report-file }}"
```

Reading outputs from a composite action step this way matches GitHub’s documented action output model [1][3][4].

## Included GitHub workflows

### `npm-publish-security.yml`
Main publish security gate workflow.

### `pr-security-check.yml`
Runs checks on pull requests so secrets or leaks are blocked before merge.

### `scheduled-audit.yml`
Runs recurring security scans to catch newly disclosed dependency issues.

### `example-consumer-ci.yml`
Shows developers exactly how to consume the CI plugin.

## Recommended package.json scripts

```json
{
  "scripts": {
    "scan": "node scripts/run-all-scans.js",
    "scan:sourcemaps": "node scripts/scan-sourcemaps.js",
    "scan:secrets": "node scripts/scan-secrets.js",
    "scan:files": "node scripts/scan-unintended-files.js",
    "scan:deps": "node scripts/scan-dependencies.js",
    "prepublishOnly": "npm run build && npm run scan"
  }
}
```

## How it works

The scanner does not guess what may be published. It asks npm directly.

```text
npm pack --dry-run --json
        │
        ├── sourcemap scan
        ├── secret scan
        ├── unintended file scan
        └── dependency scan
                │
                └── npm-security-report.json
```

This tarball-first approach is important because many leaks happen in built output rather than source files.

## Example findings this repo can prevent

- A React library accidentally publishes `dist/index.js.map`.
- A build pipeline ships `.env.production` into the tarball.
- `.npmrc` containing an auth token is included in the published package.
- A developer checks in a fake-looking token that is actually valid.
- A test fixture containing private certificates gets published.
- A package includes internal CI files or large local artifacts by mistake.

## Configuration

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ALLOWED_MAP_FILES` | empty | Approved `.map` file names. |
| `AUDIT_LEVEL` | `high` | Minimum `npm audit` threshold. |
| `MAX_FILE_MB` | `5` | Max single file size. |
| `MAX_TOTAL_MB` | `50` | Max total package size. |

### Custom rules

Use `rules/custom-patterns.json` to add organization-specific token formats.

Example:

```json
{
  "patterns": [
    {
      "name": "Internal API Token",
      "regex": "MYCO_[A-Z0-9]{32}",
      "severity": "HIGH"
    }
  ]
}
```

### Allowlist rules

Use `rules/allowlist.json` to document approved exceptions with reason, owner, and expiry.

Best practice: keep allowlists small, reviewed, and time-bound.

## Security best practices this repo supports

- `npm ci --ignore-scripts` prevents CI from running arbitrary install scripts during dependency installation.
- PR gating blocks risky changes before merge.
- scheduled audits catch issues introduced after code was written.
- JSON artifacts provide traceability for security review.
- tarball inspection validates the true publish output.
- composite-action standardization makes policy reusable across teams.

CI/CD and GitHub security guidance consistently recommend security checks and approval gates in CI, secret scanning, branch protection, and least-privilege workflow design as part of a layered repository defense strategy [5][6][7].

## Trusted publishing recommendation

For npm publishing, prefer **trusted publishing** from GitHub Actions instead of long-lived npm tokens. npm documents trusted publishing for GitHub Actions and notes that provenance attestations are generated automatically when trusted publishing is used [8]. GitHub also announced trusted publishing with OIDC as generally available and notes that npm provenance is automatic, so the old `--provenance` flag is no longer required in that model [9].

Practical guidance:

- Use GitHub-hosted runners for trusted publishing.
- Configure the trusted publisher on npm using the workflow filename in `.github/workflows/`.
- Remove long-lived publish tokens where possible.
- Keep workflow permissions minimal.

## Secret scanning beyond this repo

This repository includes its own secret scanner, but teams should also consider layered controls such as Gitleaks in pull requests and commit-history scans. Gitleaks provides an official GitHub Action for scanning repositories and CI runs, which makes it useful as a second line of defense alongside pre-publish tarball scanning [10][11].

## Multi-repo adoption guidance

For one repository, the included scripts plus the composite action are usually enough.

For many repositories:

- keep scanner logic in a shared action,
- define organization defaults through reusable workflows,
- require passing checks through branch protection,
- centralize JSON reports or SARIF where needed,
- periodically review allowlists and custom secret rules.

Composite actions are ideal for reusable step bundles, while reusable workflows are better for standardizing larger job or pipeline structure across repositories [1][2][12].

## Troubleshooting

### The scanner fails because of `.map` files

- turn off production sourcemaps in your bundler,
- remove `.map` files from the publish boundary,
- or explicitly allow only approved map files.

### The scanner finds a secret

- assume it may be valid,
- rotate it immediately,
- remove it from code and history if needed,
- re-run the scan.

### The scanner says too many files are being published

- add a strict `files` allowlist in `package.json`,
- tighten `.npmignore`,
- inspect `npm pack --dry-run --json` output directly.

### CI passes locally but fails in GitHub Actions

- ensure the build output exists in CI,
- confirm your install command does not skip required build deps,
- verify `npm ci --ignore-scripts` is compatible with your project.

## Developer checklist

Before merging or publishing:

- [ ] Run `npm run scan`
- [ ] Review the `npm pack --dry-run --json` output
- [ ] Confirm no `.map` files are shipped unintentionally
- [ ] Confirm no `.env`, `.npmrc`, or cert files are included
- [ ] Review dependency audit output
- [ ] Rotate any leaked credentials immediately
- [ ] Keep allowlists documented and temporary

## Documentation in this repo

- `docs/SECURITY.md` — security policy and disclosure guidance
- `docs/RUNBOOK.md` — incident response steps for leaks and bad publishes
- `rules/custom-patterns.json` — org-specific secret rules
- `rules/allowlist.json` — approved exceptions

## Who this is for

- library maintainers publishing public npm packages,
- internal platform teams,
- DevSecOps and CI/CD security teams,
- organizations standardizing release protections across many repositories.

## License

MIT
