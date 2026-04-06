#!/usr/bin/env node
const path = require('path');
const { color, getPolicy, getPackedFiles, matchesAllowedFile, makeFinding, printFindings, writeReport, parseNumber } = require('./lib');

const REPORT_FILE = 'scan-unintended-files.report.json';
const SCANNER = 'unintended-files-scanner';
const BLOCKED_EXACT = new Set([
  '.env', '.env.local', '.env.production', '.env.development', '.env.test', '.npmrc', '.yarnrc', '.yarnrc.yml',
  '.bash_history', '.zsh_history', '.sentryclirc', 'terraform.tfvars', 'aws-exports.js', 'firebase.json',
  'local.settings.json', 'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'
]);
const BLOCKED_EXTENSIONS = new Set(['.pem', '.key', '.p12', '.pfx', '.crt', '.csr', '.jks', '.keystore', '.pkcs8', '.ppk', '.p8', '.asc']);
const BLOCKED_PATTERNS = [
  { regex: /^\.env\./i, name: '.env variant', severity: 'HIGH' },
  { regex: /(^|\/)secrets?\//i, name: 'secrets directory', severity: 'HIGH' },
  { regex: /(^|\/)credentials?\//i, name: 'credentials directory', severity: 'HIGH' },
  { regex: /(^|\/)private\//i, name: 'private directory', severity: 'MEDIUM' },
  { regex: /(^|\/)__tests__\//, name: 'test directory', severity: 'LOW' },
  { regex: /\.(test|spec)\.(js|ts|jsx|tsx)$/i, name: 'test file', severity: 'LOW' },
  { regex: /(^|\/)coverage\//, name: 'coverage directory', severity: 'LOW' },
  { regex: /(^|\/)\.github\/workflows\//, name: 'workflow file', severity: 'LOW' },
  { regex: /\.(zip|tar|tgz|gz|7z)$/i, name: 'nested archive', severity: 'MEDIUM' },
  { regex: /\.(exe|dll|so|dylib|node)$/i, name: 'binary artifact', severity: 'MEDIUM' }
];

function main() {
  console.log(color('bold', '\n📦 Unintended Files Scanner v2\n'));
  const maxFileMb = parseNumber(process.env.MAX_FILE_MB, 5);
  const maxTotalMb = parseNumber(process.env.MAX_TOTAL_MB, 50);
  const { allowlist } = getPolicy();
  const allowedFiles = Array.isArray(allowlist.allowedFiles) ? allowlist.allowedFiles : [];
  const findings = [];
  const packed = getPackedFiles();

  if (!packed.ok) {
    findings.push(makeFinding({
      scanner: SCANNER,
      severity: 'HIGH',
      type: 'pack-failure',
      file: null,
      message: 'npm pack --dry-run failed, unable to verify tarball contents',
      evidence: packed.error
    }));
  } else {
    let totalBytes = 0;
    console.log(color('cyan', `▶ Checking ${packed.files.length} packed file(s)`));
    for (const entry of packed.files) {
      const rel = entry.path;
      const basename = path.basename(rel);
      const ext = path.extname(rel).toLowerCase();
      const size = Number(entry.size || 0);
      totalBytes += size;
      if (matchesAllowedFile(rel, allowedFiles)) continue;

      if (BLOCKED_EXACT.has(basename)) {
        findings.push(makeFinding({ scanner: SCANNER, severity: 'HIGH', type: 'blocked-file', file: rel, message: `Blocked file will be published: ${basename}`, evidence: rel }));
        continue;
      }
      if (BLOCKED_EXTENSIONS.has(ext)) {
        findings.push(makeFinding({ scanner: SCANNER, severity: 'HIGH', type: 'blocked-extension', file: rel, message: `Blocked file extension will be published: ${ext}`, evidence: rel }));
        continue;
      }
      for (const rule of BLOCKED_PATTERNS) {
        if (rule.regex.test(rel)) {
          findings.push(makeFinding({ scanner: SCANNER, severity: rule.severity, type: 'path-policy', file: rel, message: `Unexpected published file matched policy: ${rule.name}`, evidence: rel }));
        }
      }
      if (size > maxFileMb * 1024 * 1024) {
        findings.push(makeFinding({ scanner: SCANNER, severity: 'MEDIUM', type: 'file-too-large', file: rel, message: `Published file exceeds size policy (${maxFileMb} MB)`, evidence: `${(size / 1024 / 1024).toFixed(2)} MB` }));
      }
    }
    const totalMb = totalBytes / 1024 / 1024;
    if (totalMb > maxTotalMb) {
      findings.push(makeFinding({ scanner: SCANNER, severity: 'MEDIUM', type: 'package-too-large', file: null, message: `Package exceeds total size policy (${maxTotalMb} MB)`, evidence: `${totalMb.toFixed(2)} MB` }));
    }
  }

  const report = writeReport(REPORT_FILE, SCANNER, findings, {
    policy: { maxFileMb, maxTotalMb }
  });
  printFindings(findings);
  if (report.overall === 'PASS') {
    console.log(color('green', '\n✓ No blocked publish files detected.\n'));
    process.exit(0);
  }
  console.error(color('red', `\n✗ ${report.summary.high} HIGH severity file finding(s). Blocking publish.\n`));
  process.exit(1);
}

main();
