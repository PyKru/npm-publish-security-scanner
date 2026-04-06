#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const {
  color,
  relPath,
  maskSecret,
  getPolicy,
  loadCustomSecretPatterns,
  getPackedFiles,
  matchesAllowedSecret,
  makeFinding,
  printFindings,
  writeReport,
  fingerprint
} = require('./lib');

const REPORT_FILE = 'scan-secrets.report.json';
const SCANNER = 'secret-scanner';
const TEXT_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.json', '.yaml', '.yml', '.env', '.txt', '.md', '.npmrc', '.sh', '.bash', '.zsh', '.properties', '.conf', '.ini', '.html', '.css']);
const MAX_FILE_BYTES = 1024 * 1024 * 3;
const ENTROPY_THRESHOLD = 4.5;
const HIGH_ENTROPY_RX = /(["'`])([A-Za-z0-9+\/=_.!@#$%^&*:-]{20,})\1/g;

const BUILTIN_PATTERNS = [
  { name: 'AWS Access Key', regex: /\bAKIA[0-9A-Z]{16}\b/g, severity: 'HIGH' },
  { name: 'AWS Secret Access Key', regex: /aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key\s*[:=]\s*["']?[A-Za-z0-9\/+=]{40}["']?/ig, severity: 'HIGH' },
  { name: 'GitHub PAT classic', regex: /ghp_[A-Za-z0-9]{36}/g, severity: 'HIGH' },
  { name: 'GitHub Actions token', regex: /ghs_[A-Za-z0-9]{36}/g, severity: 'HIGH' },
  { name: 'GitHub fine-grained PAT', regex: /github_pat_[A-Za-z0-9_]{82,}/g, severity: 'HIGH' },
  { name: 'npm auth token line', regex: /\/\/registry\.npmjs\.org\/:_authToken\s*=\s*[^\s"']+/ig, severity: 'HIGH' },
  { name: 'npm token', regex: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: 'HIGH' },
  { name: 'Stripe live secret', regex: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'HIGH' },
  { name: 'Slack bot token', regex: /xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9-]{20,}/g, severity: 'HIGH' },
  { name: 'SendGrid API key', regex: /SG\.[A-Za-z0-9\-_]{16,}\.[A-Za-z0-9\-_]{16,}/g, severity: 'HIGH' },
  { name: 'Google API key', regex: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'HIGH' },
  { name: 'OpenAI-style key', regex: /sk-[A-Za-z0-9]{32,}/g, severity: 'HIGH' },
  { name: 'JWT', regex: /eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+/g, severity: 'MEDIUM' },
  { name: 'RSA private key', regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g, severity: 'HIGH' },
  { name: 'OpenSSH private key', regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g, severity: 'HIGH' },
  { name: 'PKCS8 private key', regex: /-----BEGIN PRIVATE KEY-----/g, severity: 'HIGH' },
  { name: 'EC private key', regex: /-----BEGIN EC PRIVATE KEY-----/g, severity: 'HIGH' },
  { name: 'PGP private key', regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, severity: 'HIGH' },
  { name: 'Generic password assignment', regex: /(?:password|passwd|pwd|secret)\s*[:=]\s*["'][^"'\n]{8,}["']/ig, severity: 'LOW' },
  { name: '.env filename', regex: /^\.env(?:\.[A-Za-z0-9_-]+)?$/i, severity: 'HIGH', filenameOnly: true }
];

function shannonEntropy(value) {
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) || 0) + 1);
  let sum = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    sum -= p * Math.log2(p);
  }
  return sum;
}

function shouldScanAsText(filePath, stat) {
  const ext = path.extname(filePath).toLowerCase();
  if (TEXT_EXTENSIONS.has(ext)) return true;
  if (stat.size > MAX_FILE_BYTES) return false;
  return ['README', 'LICENSE', '.npmrc'].includes(path.basename(filePath)) || ext === '';
}

function safeReadText(filePath) {
  try {
    const buf = fs.readFileSync(filePath);
    if (buf.includes(0)) return null;
    return buf.toString('utf8');
  } catch {
    return null;
  }
}

function collectTargetFiles() {
  const packed = getPackedFiles();
  if (!packed.ok) {
    const failFinding = makeFinding({
      scanner: SCANNER,
      severity: 'HIGH',
      type: 'pack-failure',
      file: null,
      message: 'npm pack --dry-run failed, unable to derive publish artifact set',
      evidence: packed.error
    });
    return { packed, files: [], preFindings: [failFinding] };
  }
  const files = packed.files.map((entry) => ({ path: entry.path, size: entry.size || 0 }));
  return { packed, files, preFindings: [] };
}

function main() {
  console.log(color('bold', '\n🔐 Secret Scanner v2\n'));
  const { allowlist } = getPolicy();
  const allowedSecretPatterns = Array.isArray(allowlist.allowedSecretPatterns) ? allowlist.allowedSecretPatterns : [];
  const patterns = [...BUILTIN_PATTERNS, ...loadCustomSecretPatterns()];
  const { packed, files, preFindings } = collectTargetFiles();
  const findings = [...preFindings];
  const dedupe = new Set();

  if (packed.ok) {
    console.log(color('cyan', `▶ Scanning ${files.length} packed file(s) from npm pack --dry-run`));
  } else {
    console.log(color('red', '▶ npm pack --dry-run failed; failing closed'));
  }

  for (const entry of files) {
    const abs = path.resolve(process.cwd(), entry.path);
    if (!fs.existsSync(abs)) continue;
    const stat = fs.statSync(abs);
    const relative = relPath(abs);
    const base = path.basename(relative);

    for (const pattern of patterns.filter((p) => p.filenameOnly)) {
      if (pattern.regex.test(base) && !matchesAllowedSecret(relative, base, allowedSecretPatterns)) {
        const finding = makeFinding({
          scanner: SCANNER,
          severity: pattern.severity,
          type: 'filename-secret-indicator',
          file: relative,
          message: `Sensitive filename matched pattern: ${pattern.name}`,
          evidence: base,
          metadata: { pattern: pattern.name }
        });
        if (!dedupe.has(finding.id)) {
          findings.push(finding);
          dedupe.add(finding.id);
        }
      }
    }

    if (!shouldScanAsText(relative, stat)) continue;
    const text = safeReadText(abs);
    if (!text) continue;
    const lines = text.split(/\r?\n/);

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      for (const pattern of patterns.filter((p) => !p.filenameOnly)) {
        pattern.regex.lastIndex = 0;
        let match;
        while ((match = pattern.regex.exec(line)) !== null) {
          const raw = match[0];
          if (matchesAllowedSecret(relative, raw, allowedSecretPatterns)) continue;
          const finding = makeFinding({
            scanner: SCANNER,
            severity: pattern.severity,
            type: 'secret-pattern-match',
            file: relative,
            line: i + 1,
            message: `Potential secret detected: ${pattern.name}`,
            evidence: `${maskSecret(raw)} [sha256:${fingerprint([raw])}]`,
            metadata: { pattern: pattern.name }
          });
          if (!dedupe.has(finding.id)) {
            findings.push(finding);
            dedupe.add(finding.id);
          }
          if (match.index === pattern.regex.lastIndex) pattern.regex.lastIndex += 1;
        }
      }

      HIGH_ENTROPY_RX.lastIndex = 0;
      let entropyMatch;
      while ((entropyMatch = HIGH_ENTROPY_RX.exec(line)) !== null) {
        const raw = entropyMatch[2];
        if (raw.length < 20) continue;
        if (shannonEntropy(raw) < ENTROPY_THRESHOLD) continue;
        if (/^(?:https?:|[./]|[A-Z_]+$)/.test(raw)) continue;
        if (matchesAllowedSecret(relative, raw, allowedSecretPatterns)) continue;
        const finding = makeFinding({
          scanner: SCANNER,
          severity: 'MEDIUM',
          type: 'high-entropy-string',
          file: relative,
          line: i + 1,
          message: 'High-entropy string detected in publish artifact',
          evidence: `${maskSecret(raw)} [sha256:${fingerprint([raw])}]`,
          metadata: { entropy: Number(shannonEntropy(raw).toFixed(2)) }
        });
        if (!dedupe.has(finding.id)) {
          findings.push(finding);
          dedupe.add(finding.id);
        }
        if (entropyMatch.index === HIGH_ENTROPY_RX.lastIndex) HIGH_ENTROPY_RX.lastIndex += 1;
      }
    }
  }

  const report = writeReport(REPORT_FILE, SCANNER, findings, {
    packedFilesScanned: files.length,
    policy: { allowlistedSecretPatterns: allowedSecretPatterns.length }
  });

  printFindings(findings);
  if (report.overall === 'PASS') {
    console.log(color('green', '\n✓ No HIGH severity secret findings detected.\n'));
    process.exit(0);
  }

  console.error(color('red', `\n✗ ${report.summary.high} HIGH severity secret finding(s) detected. Blocking publish.\n`));
  process.exit(1);
}

main();
