#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const {
  color, relPath, getPolicy, getPackedFiles, matchesAllowedFile,
  makeFinding, printFindings, writeReport, fingerprint, shannonEntropy
} = require('./lib');

const REPORT_FILE = 'scan-sourcemaps.report.json';
const SCANNER = 'sourcemap-scanner';
const ENTROPY_THRESHOLD = 4.5;
const HIGH_ENTROPY_RX = /[\"'`]([A-Za-z0-9+\\/=_.!@#$%^&*:-]{20,})[\"`']/g;
const MAP_EXT = '.map';

function parseSourcemap(mapPath) {
  try {
    const content = fs.readFileSync(mapPath, 'utf8');
    const jsonMatch = content.match(/^{.*}$/s);
    if (!jsonMatch) return null;
    const mapJson = JSON.parse(jsonMatch[0]);
    if (!mapJson.sections && mapJson.sourcesContent && mapJson.sourcesContent.length > 0) {
      return mapJson.sourcesContent.filter(Boolean);
    }
    // Handle indexed sourcemaps (basic)
    if (mapJson.sections) {
      for (const section of mapJson.sections) {
        if (section.map && section.map.sourcesContent && section.map.sourcesContent.length > 0) {
          return section.map.sourcesContent.filter(Boolean);
        }
      }
    }
    return [];
  } catch {
    return null;
  }
}

function hasHighEntropy(content) {
  HIGH_ENTROPY_RX.lastIndex = 0;
  let match;
  while ((match = HIGH_ENTROPY_RX.exec(content)) !== null) {
    const candidate = match[1];
    if (candidate.length >= 20 && shannonEntropy(candidate) >= ENTROPY_THRESHOLD &&
        /^(?:https?:|[./]|[A-Z_]+$)/.test(candidate)) continue;
    return true;
  }
  return false;
}

function main() {
  console.log(color('bold', '\n🗺️  Sourcemap Scanner v1\n'));
  const { allowlist } = getPolicy();
  const allowedFiles = Array.isArray(allowlist.allowedFiles) ? allowlist.allowedFiles : [];
  const allowedMapFiles = (process.env.ALLOWED_MAP_FILES || '').split(',').filter(Boolean);
  const findings = [];
  const packed = getPackedFiles();

  if (!packed.ok) {
    findings.push(makeFinding({
      scanner: SCANNER,
      severity: 'HIGH',
      type: 'pack-failure',
      file: null,
      message: 'npm pack --dry-run failed, unable to check sourcemaps',
      evidence: packed.error
    }));
  } else {
    console.log(color('cyan', `▶ Checking ${packed.files.length} packed files for sourcemaps`));
    for (const entry of packed.files) {
      const relPathStr = entry.path;
      if (!relPathStr.endsWith(MAP_EXT) || matchesAllowedFile(relPathStr, allowedFiles) ||
          allowedMapFiles.some(f => relPathStr.includes(f.trim()))) {
        continue;
      }
      const absPath = path.resolve(process.cwd(), relPathStr);
      if (!fs.existsSync(absPath)) continue;
      const sources = parseSourcemap(absPath);
      if (!sources || sources.length === 0) {
        findings.push(makeFinding({
          scanner: SCANNER,
          severity: 'MEDIUM',
          type: 'sourcemap-present',
          file: relPathStr,
          message: `Sourcemap found in publish package (may leak source)`,
          evidence: relPathStr
        }));
        continue;
      }
      findings.push(makeFinding({
        scanner: SCANNER,
        severity: 'HIGH',
        type: 'sourcemap-sources-leak',
        file: relPathStr,
        message: `Sourcemap exposes ${sources.length} source file(s) content`,
        evidence: `${sources.length} files [sha256:${fingerprint(sources.map(s => s.slice(0, 50)))}]`
      }));
      for (let i = 0; i < sources.length; i++) {
        const source = sources[i];
        if (hasHighEntropy(source)) {
          findings.push(makeFinding({
            scanner: SCANNER,
            severity: 'HIGH',
            type: 'sourcemap-entropy-leak',
            file: relPathStr,
            message: `High-entropy data in sourcemap sourceContent[${i}]`,
            evidence: `[sha256:${fingerprint([source.slice(0, 100)])}]`
          }));
        }
      }
    }
  }

  const report = writeReport(REPORT_FILE, SCANNER, findings, {
    allowedMapFiles: allowedMapFiles.length,
    policy: { allowedMapFiles: process.env.ALLOWED_MAP_FILES }
  });
  printFindings(findings);
  if (report.overall === 'PASS') {
    console.log(color('green', '\n✓ No critical sourcemap issues.\n'));
    process.exit(0);
  }
  console.error(color('red', `\n✗ ${report.summary.high} HIGH severity sourcemap findings. Blocking publish.\n`));
  process.exit(1);
}

main();
