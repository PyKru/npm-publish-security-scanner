#!/usr/bin/env node
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const c = (col, t) => `\x1b[${{red:'31',yellow:'33',green:'32',cyan:'36',bold:'1',dim:'2'}[col]}m${t}\x1b[0m`;

const SCANNERS = [
  { name: 'Sourcemap Leak Scanner', script: 'scan-sourcemaps.js', report: 'scan-sourcemaps.report.json', critical: true },
  { name: 'Secret Scanner', script: 'scan-secrets.js', report: 'scan-secrets.report.json', critical: true },
  { name: 'Unintended Files Scanner', script: 'scan-unintended-files.js', report: 'scan-unintended-files.report.json', critical: true },
  { name: 'Dependency Scanner', script: 'scan-dependencies.js', report: 'scan-dependencies.report.json', critical: false }
];

console.log(c('cyan', `
╔══════════════════════════════════════════════════════════╗
║     npm Publish Security Scanner  v1.1.0                ║
║  Protecting releases from leaks, secrets & bloat        ║
╚══════════════════════════════════════════════════════════╝
`));

const results = [];
let overallFailed = false;

SCANNERS.forEach(({ name, script, report, critical }) => {
  const start = Date.now();
  const result = spawnSync(process.execPath, [path.join(__dirname, script)], {
    stdio: 'inherit',
    env: { ...process.env }
  });
  const passed = result.status === 0;
  let reportData = {};
  try {
    reportData = JSON.parse(fs.readFileSync(report, 'utf8'));
  } catch {}
  results.push({ scanner: name, passed, duration: Date.now() - start, critical, report: reportData });
  if (!passed && critical) overallFailed = true;
  console.log('');
});

console.log(c('bold', '─'.repeat(60)));
console.log(c('bold', ' SCAN SUMMARY'));
console.log(c('bold', '─'.repeat(60)));
results.forEach(({ scanner, passed, duration, critical }) => {
  const icon = passed ? c('green', '✓') : c('red', '✗');
  const label = passed ? c('green', 'PASS') : (critical ? c('red', 'FAIL') : c('yellow', 'WARN'));
  console.log(`  ${icon}  ${label}  ${scanner.padEnd(34)} ${c('dim', duration + 'ms')}`);
});
console.log(c('bold', '─'.repeat(60)));

const report = {
  timestamp: new Date().toISOString(),
  repository: process.env.GITHUB_REPOSITORY || 'local',
  commit: process.env.GITHUB_SHA ? process.env.GITHUB_SHA.slice(0, 7) : 'local',
  overall: overallFailed ? 'FAIL' : 'PASS',
  scanners: results
};

fs.writeFileSync('npm-security-report.json', JSON.stringify(report, null, 2));
console.log(c('dim', '\n  Report → npm-security-report.json'));

if (overallFailed) {
  console.error(c('red', c('bold', '\n🚨 PUBLISH BLOCKED — Critical security violations found.\n')));
  process.exit(1);
}

console.log(c('green', c('bold', '\n✅ All critical checks passed. Safe to publish.\n')));
process.exit(0);
