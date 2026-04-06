#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { color, writeJson } = require('./lib');

const SCANNERS = [
  { name: 'Sourcemap Scanner', script: 'scan-sourcemaps.js', report: 'scan-sourcemaps.report.json', critical: true },
  { name: 'Secret Scanner', script: 'scan-secrets.js', report: 'scan-secrets.report.json', critical: true },
  { name: 'Unintended Files Scanner', script: 'scan-unintended-files.js', report: 'scan-unintended-files.report.json', critical: true },
  { name: 'Dependency Scanner', script: 'scan-dependencies.js', report: 'scan-dependencies.report.json', critical: false }
];

console.log(color('cyan', '\n╔══════════════════════════════════════════════╗'));
console.log(color('cyan', '║ npm Publish Security Scanner v2             ║'));
console.log(color('cyan', '║ Hardened pre-publish security gate          ║'));
console.log(color('cyan', '╚══════════════════════════════════════════════╝\n'));

const results = [];
let overallFailed = false;
for (const scanner of SCANNERS) {
  const startedAt = Date.now();
  const child = spawnSync(process.execPath, [path.join(__dirname, scanner.script)], {
    stdio: 'inherit',
    env: { ...process.env }
  });
  let report = null;
  try { report = JSON.parse(fs.readFileSync(scanner.report, 'utf8')); } catch {}
  const passed = child.status === 0;
  if (!passed && scanner.critical) overallFailed = true;
  results.push({
    scanner: scanner.name,
    script: scanner.script,
    critical: scanner.critical,
    exitCode: child.status,
    passed,
    durationMs: Date.now() - startedAt,
    report
  });
  console.log('');
}

console.log(color('bold', '─'.repeat(68)));
console.log(color('bold', ' SCAN SUMMARY'));
console.log(color('bold', '─'.repeat(68)));
for (const result of results) {
  const icon = result.passed ? color('green', '✓') : color(result.critical ? 'red' : 'yellow', '✗');
  const label = result.passed ? color('green', 'PASS') : color(result.critical ? 'red' : 'yellow', result.critical ? 'FAIL' : 'WARN');
  console.log(` ${icon} ${label} ${result.scanner.padEnd(28)} ${color('dim', `${result.durationMs}ms`)}`);
}
console.log(color('bold', '─'.repeat(68)));

const consolidated = {
  schemaVersion: '2.0',
  timestamp: new Date().toISOString(),
  repository: process.env.GITHUB_REPOSITORY || 'local',
  commit: process.env.GITHUB_SHA || 'local',
  overall: overallFailed ? 'FAIL' : 'PASS',
  scanners: results
};
writeJson('npm-security-report.json', consolidated);
console.log(color('dim', '\nReport -> npm-security-report.json'));

if (overallFailed) {
  console.error(color('red', '\n🚨 PUBLISH BLOCKED — critical security findings detected.\n'));
  process.exit(1);
}
console.log(color('green', '\n✅ All critical checks passed.\n'));
process.exit(0);
