#!/usr/bin/env node
const fs = require('fs');
const { spawnSync } = require('child_process');
const { color, makeFinding, printFindings, writeReport } = require('./lib');

const REPORT_FILE = 'scan-dependencies.report.json';
const SCANNER = 'dependency-scanner';
const DEV_ONLY = new Set(['jest', 'mocha', 'chai', 'sinon', 'nyc', 'istanbul', 'ts-jest', 'eslint', 'prettier', 'husky', 'lint-staged', 'nodemon', 'ts-node', 'webpack', 'rollup', 'vite', 'esbuild', 'parcel', 'cypress', 'playwright', 'puppeteer']);
const TYPOSQUAT_PATTERNS = [/^1odash$/, /^lod[a4]sh$/, /^expr[e3]ss$/, /^expresss$/, /^re[4a]ct$/, /^reakt$/, /^cross-[e3]nv$/, /^c[0o]lors$/];

function runAudit(level) {
  return spawnSync('npm', ['audit', `--audit-level=${level}`, '--json'], {
    cwd: process.cwd(),
    encoding: 'utf8',
    shell: process.platform === 'win32'
  });
}

function main() {
  console.log(color('bold', '\n🔍 Dependency Scanner v2\n'));
  const findings = [];
  const auditLevel = process.env.AUDIT_LEVEL || 'high';
  console.log(color('cyan', `▶ Running npm audit (${auditLevel})`));
  const audit = runAudit(auditLevel);
  if (audit.status !== 0) {
    try {
      const parsed = JSON.parse(audit.stdout || '{}');
      const meta = parsed.metadata?.vulnerabilities || {};
      if ((meta.critical || 0) > 0) findings.push(makeFinding({ scanner: SCANNER, severity: 'HIGH', type: 'npm-audit', file: null, message: `npm audit reported ${meta.critical} critical vulnerability finding(s)`, evidence: 'critical' }));
      if ((meta.high || 0) > 0) findings.push(makeFinding({ scanner: SCANNER, severity: 'HIGH', type: 'npm-audit', file: null, message: `npm audit reported ${meta.high} high vulnerability finding(s)`, evidence: 'high' }));
      if ((meta.moderate || 0) > 0) findings.push(makeFinding({ scanner: SCANNER, severity: 'MEDIUM', type: 'npm-audit', file: null, message: `npm audit reported ${meta.moderate} moderate vulnerability finding(s)`, evidence: 'moderate' }));
    } catch {
      findings.push(makeFinding({ scanner: SCANNER, severity: 'MEDIUM', type: 'audit-parse-failure', file: null, message: 'npm audit failed and JSON output could not be parsed', evidence: audit.stderr || audit.stdout }));
    }
  }

  if (!fs.existsSync('package.json')) {
    findings.push(makeFinding({ scanner: SCANNER, severity: 'HIGH', type: 'missing-package-json', file: null, message: 'package.json not found', evidence: process.cwd() }));
  } else {
    const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
    const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.peerDependencies || {}) };
    for (const dep of Object.keys(allDeps)) {
      if (TYPOSQUAT_PATTERNS.some((rx) => rx.test(dep))) {
        findings.push(makeFinding({ scanner: SCANNER, severity: 'HIGH', type: 'typosquat-suspect', file: 'package.json', message: `Possible typosquatted dependency detected: ${dep}`, evidence: dep }));
      }
    }

    for (const dep of Object.keys(pkg.dependencies || {})) {
      if (DEV_ONLY.has(dep)) {
        findings.push(makeFinding({ scanner: SCANNER, severity: 'MEDIUM', type: 'dev-tool-in-prod-deps', file: 'package.json', message: `Development tool appears in production dependencies: ${dep}`, evidence: dep }));
      }
    }

    const lifecycleScripts = ['prepublish', 'prepublishOnly', 'prepare', 'install', 'postinstall'];
    for (const scriptName of lifecycleScripts) {
      if (pkg.scripts && pkg.scripts[scriptName]) {
        findings.push(makeFinding({ scanner: SCANNER, severity: scriptName === 'postinstall' || scriptName === 'install' ? 'HIGH' : 'MEDIUM', type: 'lifecycle-script', file: 'package.json', message: `Lifecycle script present: ${scriptName}`, evidence: String(pkg.scripts[scriptName]).slice(0, 120) }));
      }
    }

    const suspiciousSources = [];
    for (const [name, spec] of Object.entries(pkg.dependencies || {})) {
      if (/^(git\+|https?:|file:|link:)/i.test(String(spec))) suspiciousSources.push(`${name}@${spec}`);
      if (/^[~^]/.test(String(spec))) {
        findings.push(makeFinding({ scanner: SCANNER, severity: 'LOW', type: 'non-exact-version', file: 'package.json', message: `Non-exact production dependency version: ${name}@${spec}`, evidence: `${name}@${spec}` }));
      }
    }
    for (const source of suspiciousSources) {
      findings.push(makeFinding({ scanner: SCANNER, severity: 'HIGH', type: 'non-registry-dependency', file: 'package.json', message: 'Dependency uses non-registry source', evidence: source }));
    }
  }

  if (!fs.existsSync('package-lock.json') && !fs.existsSync('pnpm-lock.yaml') && !fs.existsSync('yarn.lock')) {
    findings.push(makeFinding({ scanner: SCANNER, severity: 'HIGH', type: 'missing-lockfile', file: null, message: 'No lockfile found in repository', evidence: 'package-lock.json | pnpm-lock.yaml | yarn.lock' }));
  }

  const report = writeReport(REPORT_FILE, SCANNER, findings, { auditLevel });
  printFindings(findings);
  if (report.overall === 'PASS') {
    console.log(color('green', '\n✓ Dependency checks passed.\n'));
    process.exit(0);
  }
  console.error(color('red', `\n✗ ${report.summary.high} HIGH severity dependency finding(s).\n`));
  process.exit(1);
}

main();
