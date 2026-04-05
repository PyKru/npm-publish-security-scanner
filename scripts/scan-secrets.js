#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const colors = { red:'31', yellow:'33', green:'32', cyan:'36', bold:'1', dim:'2' };
const c = (col, t) => `\x1b[${colors[col]}m${t}\x1b[0m`;

function readJsonIfExists(file, fallback) {
  try {
    return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : fallback;
  } catch {
    return fallback;
  }
}

const allowlist = readJsonIfExists(path.join(process.cwd(), 'rules', 'allowlist.json'), {
  allowedSecretPatterns: []
});

const customPatternsFile = readJsonIfExists(path.join(process.cwd(), 'rules', 'custom-patterns.json'), {
  patterns: []
});

const builtInPatterns = [
  { name:'AWS Access Key', rx:/\bAKIA[0-9A-Z]{16}\b/, severity:'HIGH' },
  { name:'GitHub Token (classic)', rx:/ghp_[A-Za-z0-9]{36}/, severity:'HIGH' },
  { name:'GitHub Actions Token', rx:/ghs_[A-Za-z0-9]{36}/, severity:'HIGH' },
  { name:'GitHub Fine-grained PAT', rx:/github_pat_[A-Za-z0-9_]{82}/, severity:'HIGH' },
  { name:'npm Auth Token', rx:/\/\/registry\.npmjs\.org\/:_authToken\s*=\s*[A-Za-z0-9\-_\.]+/i, severity:'HIGH' },
  { name:'npm Token', rx:/\bnpm_[A-Za-z0-9]{36}\b/, severity:'HIGH' },
  { name:'Stripe Secret Key', rx:/sk_live_[0-9a-zA-Z]{24,}/, severity:'HIGH' },
  { name:'OpenAI API Key', rx:/sk-[A-Za-z0-9]{48}/, severity:'HIGH' },
  { name:'Google API Key', rx:/AIza[0-9A-Za-z\-_]{35}/, severity:'HIGH' },
  { name:'RSA Private Key', rx:/-----BEGIN (?:RSA )?PRIVATE KEY-----/, severity:'HIGH' },
  { name:'EC Private Key', rx:/-----BEGIN EC PRIVATE KEY-----/, severity:'HIGH' },
  { name:'PGP Private Key', rx:/-----BEGIN PGP PRIVATE KEY BLOCK-----/, severity:'HIGH' },
  { name:'JWT Token', rx:/eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+/, severity:'MEDIUM' },
  { name:'.env file', rx:/^\.env(?:\.[a-z]+)?$/i, severity:'HIGH', filenameOnly:true }
];

const customPatterns = (customPatternsFile.patterns || [])
  .filter((p) => p.name && p.regex && p.severity)
  .map((p) => ({ name: p.name, rx: new RegExp(p.regex), severity: p.severity }));

const SECRET_PATTERNS = [...builtInPatterns, ...customPatterns];
const HIGH_ENTROPY_RX = /['"][A-Za-z0-9+/=!@#$%^&*_\-]{20,}['"]/g;
const ENTROPY_THRESHOLD = 4.5;
const SKIP_EXT = new Set(['.png','.jpg','.gif','.svg','.woff','.woff2','.ttf','.ico','.map']);
const SKIP_DIR = new Set(['node_modules','.git','coverage','__tests__','fixtures']);

let violations = 0;
let lowCount = 0;
const findings = [];

function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  return Object.values(freq).reduce((acc, n) => {
    const p = n / str.length;
    return acc - p * Math.log2(p);
  }, 0);
}

function isAllowlisted(match, filePath) {
  return (allowlist.allowedSecretPatterns || []).some((entry) => {
    if (!entry.pattern) return false;
    if (entry.expires && new Date(entry.expires) < new Date()) return false;
    if (entry.path && filePath && !filePath.includes(entry.path)) return false;
    return match.includes(entry.pattern);
  });
}

function recordFinding(file, line, pattern, severity, match) {
  if (isAllowlisted(match, file)) return;
  findings.push({ file, line, pattern, severity, match });
  if (severity === 'HIGH' || severity === 'MEDIUM') violations += 1;
  else lowCount += 1;
}

function scanFile(filePath) {
  const parts = filePath.split(path.sep);
  if (parts.some((p) => SKIP_DIR.has(p))) return;
  if (SKIP_EXT.has(path.extname(filePath).toLowerCase())) return;

  const basename = path.basename(filePath);
  for (const pattern of SECRET_PATTERNS.filter((p) => p.filenameOnly)) {
    if (pattern.rx.test(basename)) {
      recordFinding(filePath, 0, pattern.name, pattern.severity, basename);
    }
  }

  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return;
  }

  content.split('\n').forEach((line, i) => {
    for (const pattern of SECRET_PATTERNS.filter((p) => !p.filenameOnly)) {
      const match = line.match(pattern.rx);
      if (match) recordFinding(filePath, i + 1, pattern.name, pattern.severity, match[0].slice(0, 100));
    }

    for (const candidate of line.match(HIGH_ENTROPY_RX) || []) {
      const raw = candidate.slice(1, -1);
      if (shannonEntropy(raw) > ENTROPY_THRESHOLD && !isAllowlisted(raw, filePath)) {
        recordFinding(filePath, i + 1, 'High-Entropy String', 'MEDIUM', raw.slice(0, 100));
      }
    }
  });
}

console.log(c('bold', '\n🔐 Secret Scanner\n'));

let publishFiles = [];
try {
  const out = execSync('npm pack --dry-run --json', { encoding:'utf8', stdio:['ignore','pipe','ignore'] });
  publishFiles = JSON.parse(out)[0]?.files?.map((f) => f.path) || [];
} catch {}

if (publishFiles.length > 0) {
  console.log(c('cyan', `▶ Scanning ${publishFiles.length} npm tarball files...`));
  publishFiles.forEach((f) => { if (fs.existsSync(f)) scanFile(f); });
} else {
  console.log(c('cyan', '▶ Scanning project files...'));
  ['src', 'lib', 'dist', 'scripts'].forEach((dir) => {
    if (!fs.existsSync(dir)) return;
    const walk = (d) => {
      for (const entry of fs.readdirSync(d, { withFileTypes: true })) {
        const full = path.join(d, entry.name);
        if (entry.isDirectory() && !SKIP_DIR.has(entry.name)) walk(full);
        else scanFile(full);
      }
    };
    walk(dir);
  });
}

fs.writeFileSync('scan-secrets.report.json', JSON.stringify({ findings }, null, 2));

for (const sev of ['HIGH', 'MEDIUM', 'LOW']) {
  const list = findings.filter((f) => f.severity === sev);
  if (!list.length) continue;
  const col = sev === 'HIGH' ? 'red' : sev === 'MEDIUM' ? 'yellow' : 'dim';
  console.log(c(col, `\n[${sev}] ${list.length} finding(s):`));
  list.forEach((f) => {
    console.log(`  ${c(col, '●')} ${f.pattern}`);
    console.log(`    File : ${f.file}${f.line ? ':' + f.line : ''}`);
    console.log(`    Match: ${c('dim', f.match)}`);
  });
}

if (violations === 0) {
  console.log(c('green', `\n✓ No secrets detected${lowCount ? ` (${lowCount} low-severity warning(s))` : ''}.\n`));
  process.exit(0);
}

console.error(c('red', `\n✗ ${violations} HIGH/MEDIUM secret(s) found. Blocking publish.\n`));
process.exit(1);
