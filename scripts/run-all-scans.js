#!/usr/bin/env node
const fs = require('fs');
const { execSync } = require('child_process');
const path = require('path');

const SCANNERS = [
  'scan-secrets.js',
  'scan-unintended-files.js',
  'scan-sourcemaps.js'
];

function runScanner(script) {
  const reportPath = path.join(process.cwd(), `scan-${script.replace('.js', '')}.report.json`);

  try {
    execSync(`node scripts/${script}`, {
      stdio: 'inherit',
      cwd: process.cwd(),
      timeout: 30000
    });

    if (fs.existsSync(reportPath)) {
      const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
      return { name: script, report, ok: report.overall === 'PASS' };
    } else {
      // Create minimal PASS report if scanner ran successfully
      const emptyReport = {
        scanner: script.replace('.js', ''),
        overall: 'PASS',
        summary: { high: 0, medium: 0, low: 0 },
        findings: [],
        metadata: {}
      };
      fs.writeFileSync(reportPath, JSON.stringify(emptyReport, null, 2));
      return { name: script, report: emptyReport, ok: true };
    }
  } catch (err) {
    // Scanner failed - create FAIL report
    const failReport = {
      scanner: script.replace('.js', ''),
      overall: 'FAIL',
      summary: { high: 1 },
      findings: [{ severity: 'HIGH', type: 'scan-error', message: err.message }],
      error: err.message
    };
    fs.writeFileSync(reportPath, JSON.stringify(failReport, null, 2));
    return { name: script, report: failReport, ok: false };
  }
}

function writeAggregateReport(filename, data) {
  try {
    fs.writeFileSync(filename, JSON.stringify(data, null, 2) + '\n');
    console.log(`📊 Aggregate report written: ${filename}`);
  } catch (err) {
    console.error(`❌ Failed to write ${filename}: ${err.message}`);
    process.exit(1);
  }
}

function main() {
  console.log('\n🚀 Running all npm publish security scans...\n');

  const results = SCANNERS.map(runScanner);
  const numFailed = results.filter(r => !r.ok).length;

  const aggregate = {
    timestamp: new Date().toISOString(),
    scanners: results.map(r => ({
      name: r.name,
      status: r.ok ? 'PASS' : 'FAIL',
      summary: r.report?.summary || null,
      ...(r.report || {}),
      error: r.error || null
    })),
    overall: numFailed === 0 ? 'PASS' : 'FAIL',
    summary: results.reduce((acc, r) => {
      const s = r.report?.summary || { high: 0, medium: 0, low: 0 };
      acc.high += s.high || 0;
      acc.medium += s.medium || 0;
      acc.low += s.low || 0;
      return acc;
    }, { high: 0, medium: 0, low: 0 })
  };

  writeAggregateReport('npm-security-report.json', aggregate);

  console.log('\n📋 Scan Results:');
  results.forEach(r => {
    const status = r.ok ? '✅ PASS' : '❌ FAIL';
    console.log(`${status} ${r.name} ${r.error ? `(${r.error})` : ''}`);
  });

  console.log(`\nOverall: ${aggregate.overall} (${aggregate.summary.high} HIGH findings)`);

  if (numFailed > 0) {
    console.error('\n✗ Security scans failed. Publish blocked.');
    process.exit(1);
  }
  console.log('\n✓ All scans passed. Safe to publish.');
  process.exit(0);
}

main();
