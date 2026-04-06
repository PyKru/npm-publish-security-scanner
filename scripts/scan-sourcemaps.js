#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { color, getPolicy, getPackedFiles, makeFinding, printFindings, writeReport } = require('./lib');

const REPORT_FILE = 'scan-sourcemaps.report.json';
const SCANNER = 'sourcemap-scanner';
const inlineRx = /[#@]\s*sourceMappingURL=data:application\/(?:json|octet-stream)/i;
const externalRx = /[#@]\s*sourceMappingURL=([^\s]+)/g;

function main() {
  console.log(color('bold', '\n🗺 Sourcemap Scanner v2\n'));
  const { allowlist } = getPolicy();
  const envAllowed = String(process.env.ALLOWED_MAP_FILES || '')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
  const allowedMapFiles = new Set([...(allowlist.allowedMapFiles || []), ...envAllowed].map((x) => path.basename(x)));
  const packed = getPackedFiles();
  const findings = [];

  if (!packed.ok) {
    findings.push(makeFinding({
      scanner: SCANNER,
      severity: 'HIGH',
      type: 'pack-failure',
      file: null,
      message: 'npm pack --dry-run failed, unable to verify publish artifact sourcemaps',
      evidence: packed.error
    }));
  } else {
    console.log(color('cyan', `▶ Inspecting ${packed.files.length} packed file(s)`));
    for (const file of packed.files) {
      const rel = file.path;
      const abs = path.resolve(process.cwd(), rel);
      const base = path.basename(rel);
      if (rel.endsWith('.map') && !allowedMapFiles.has(base)) {
        findings.push(makeFinding({
          scanner: SCANNER,
          severity: 'HIGH',
          type: 'map-file-in-package',
          file: rel,
          message: '.map file will be published in the npm tarball',
          evidence: rel
        }));
        continue;
      }
      if (!/\.(js|mjs|cjs|css)$/.test(rel) || !fs.existsSync(abs)) continue;
      let content = '';
      try { content = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      if (inlineRx.test(content)) {
        findings.push(makeFinding({
          scanner: SCANNER,
          severity: 'HIGH',
          type: 'inline-sourcemap',
          file: rel,
          message: 'Inline sourcemap reference detected in publish artifact',
          evidence: 'sourceMappingURL=data:...'
        }));
      }
      externalRx.lastIndex = 0;
      let match;
      while ((match = externalRx.exec(content)) !== null) {
        const target = match[1].trim();
        if (!target.endsWith('.map')) continue;
        if (/^https?:\/\//i.test(target)) {
          findings.push(makeFinding({
            scanner: SCANNER,
            severity: 'MEDIUM',
            type: 'external-sourcemap-url',
            file: rel,
            message: 'External sourcemap URL referenced from published artifact',
            evidence: target
          }));
          continue;
        }
        if (!allowedMapFiles.has(path.basename(target))) {
          findings.push(makeFinding({
            scanner: SCANNER,
            severity: 'HIGH',
            type: 'sourcemap-reference',
            file: rel,
            message: 'Published artifact references a sourcemap file',
            evidence: target
          }));
        }
      }
    }
  }

  const report = writeReport(REPORT_FILE, SCANNER, findings, {
    allowedMapFiles: Array.from(allowedMapFiles).sort()
  });
  printFindings(findings);
  if (report.overall === 'PASS') {
    console.log(color('green', '\n✓ No sourcemap leaks detected.\n'));
    process.exit(0);
  }
  console.error(color('red', `\n✗ ${report.summary.high} HIGH severity sourcemap finding(s). Blocking publish.\n`));
  process.exit(1);
}

main();
