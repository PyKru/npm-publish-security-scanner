#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const c = (col, t) => `\x1b[${{ red:'31', yellow:'33', green:'32', cyan:'36', bold:'1', dim:'2' }[col]}m${t}\x1b[0m`;
const REPORT_FILE = 'scan-secrets.report.json';

const BUILTIN_PATTERNS = [
  { name: 'AWS Access Key', rx: /\bAKIA[0-9A-Z]{16}\b/g, severity: 'HIGH' },
  { name: 'AWS Secret Key', rx: /aws[_\-\s]?secret[_\-\s]?key\s*[:=]\s*["']?[A-Za-z0-9\/+=]{40}/ig, severity: 'HIGH' },
  { name: 'GitHub Token (classic)', rx: /ghp_[A-Za-z0-9]{36}/g, severity: 'HIGH' },
  { name: 'GitHub Actions Token', rx: /ghs_[A-Za-z0-9]{36}/g, severity: 'HIGH' },
  { name: 'GitHub Fine-grained PAT', rx: /github_pat_[A-Za-z0-9_]{82}/g, severity: 'HIGH' },
  { name: 'npm Auth Token', rx: /\/\/registry\.npmjs\.org\/:_authToken\s*=\s*[A-Za-z0-9\-_\.]+/ig, severity: 'HIGH' },
  { name: 'npm Token', rx: /\bnpm_[A-Za-z0-9]{36}\b/g, severity: 'HIGH' },
  { name: 'Stripe Secret Key', rx: /sk_live_[0-9a-zA-Z]{24,}/g, severity: 'HIGH' },
  { name: 'SendGrid API Key', rx: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g, severity: 'HIGH' },
  { name: 'Slack Bot Token', rx: /xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}/g, severity: 'HIGH' },
  { name: 'OpenAI API Key', rx: /sk-[A-Za-z0-9]{48}/g, severity: 'HIGH' },
  { name: 'Google API Key', rx: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'HIGH' },
  { name: 'Google Service Account', rx: /"type"\s*:\s*"service_account"/g, severity: 'HIGH' },
  { name: 'Firebase Config', rx: /apiKey\s*:\s*["'][A-Za-z0-9\-_]{39}["']/ig, severity: 'MEDIUM' },
  { name: 'JWT Token', rx: /eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+\/=]+/g, severity: 'MEDIUM' },
  { name: 'RSA Private Key', rx: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g, severity: 'HIGH' },
  { name: 'EC Private Key', rx: /-----BEGIN EC PRIVATE KEY-----/g, severity: 'HIGH' },
  { name: 'PGP Private Key', rx: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g, severity: 'HIGH' },
  { name: 'Generic Password', rx: /(?:password|passwd|pwd|secret)\s*[:=]\s*["'][^"']{8,}["']/ig, severity: 'LOW' },
  { name: 'Generic API Key', rx: /(?:api[_\-]?key|api[_\-]?secret)\s*[:=]\s*["'][A-Za-z0-9\-_\.]{16,}["']/ig, severity: 'LOW' },
  { name: '.env file', rx: /^\.env(?:\.[a-z]+)?$/i, severity: 'HIGH', filenameOnly: true },
];

function loadJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { return null; }
}
function normalize(p) { return path.relative(process.cwd(), p).replace(/\\/g, '/'); }
function expired(entry) { return !!(entry?.expires && new Date(entry.expires) < new Date()); }
function entropy(s) {
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  return Object.values(freq).reduce((a, n) => { const p = n / s.length; return a - p * Math.log2(p); }, 0);
}

function buildCustomPatterns() {
  const cfg = loadJson(path.join('rules', 'custom-patterns.json'));
  if (!cfg?.patterns) return [];
  return cfg.patterns.flatMap((p) => {
    try { return [{ name: p.name, rx: new RegExp(p.regex, 'g'), severity: p.severity || 'HIGH' }]; }
    catch (_) { return []; }
  });
}
function buildAllowlist() {
  const cfg = loadJson(path.join('rules', 'allowlist.json')) || {};
  return Array.isArray(cfg.allowedSecretPatterns) ? cfg.allowedSecretPatterns : [];
}
function isAllowed(filePath, match, allowlist) {
  const rel = normalize(filePath);
  return allowlist.some((entry) => {
    if (!entry?.pattern || expired(entry)) return false;
    if (entry.pattern !== match) return false;
    if (entry.path && entry.path.replace(/\\/g, '/') !== rel) return false;
    return true;
  });
}

const HIGH_ENTROPY_RX = /['\"][A-Za-z0-9+\/=!@#$%^&*\-_]{20,}['\"]/g;
const ENTROPY_THRESHOLD = 4.5;
const SKIP_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.ico', '.map']);
const SKIP_DIR = new Set(['node_modules', '.git', 'coverage', '__tests__', 'fixtures']);
const SECRET_PATTERNS = [...BUILTIN_PATTERNS, ...buildCustomPatterns()];
const SELF_SCAN_FILE = path.join('scripts', 'scan-secrets.js');
const ALLOWLIST = buildAllowlist();
const findings = [];
let violations = 0;
let lowCount = 0;

function addFinding(filePath, line, pattern, severity, match) {
  if (isAllowed(filePath, match, ALLOWLIST)) return;
  findings.push({ file: normalize(filePath), line, pattern, severity, match });
  if (severity === 'HIGH' || severity === 'MEDIUM') violations++;
  else lowCount++;
}

function scanFile(filePath) {
  const rel = normalize(filePath);
  const parts = rel.split('/');
  if (rel === SELF_SCAN_FILE) return;
  if (parts.some((p) => SKIP_DIR.has(p))) return;
  if (SKIP_EXT.has(path.extname(rel).toLowerCase())) return;

  const basename = path.basename(rel);
  SECRET_PATTERNS.filter((p) => p.filenameOnly).forEach((p) => {
    if (p.rx.test(basename)) addFinding(filePath, 0, p.name, p.severity, basename);
  });

  let content;
  try { content = fs.readFileSync(filePath, 'utf8'); } catch (_) { return; }
  content.split('\n').forEach((line, i) => {
    SECRET_PATTERNS.filter((p) => !p.filenameOnly).forEach((p) => {
      p.rx.lastIndex = 0;
      const m = line.match(p.rx);
      if (m?.[0]) addFinding(filePath, i + 1, p.name, p.severity, m[0].slice(0, 200));
    });
    for (const cand of (line.match(HIGH_ENTROPY_RX) || [])) {
      const raw = cand.slice(1, -1);
      if (entropy(raw) > ENTROPY_THRESHOLD) addFinding(filePath, i + 1, 'High-Entropy String', 'MEDIUM', cand.slice(0, 200));
    }
  });
}

console.log(c('bold', '\n🔐 Secret Scanner\n'));
let publishFiles = [];
try {
  const out = execSync('npm pack --dry-run --json 2>/dev/null', { encoding: 'utf8' });
  publishFiles = JSON.parse(out)[0]?.files?.map((f) => f.path) || [];
} catch (_) {}

const rootFiles = ['src', 'lib', 'dist', 'scripts', 'README.md'];
if (publishFiles.length > 0) {
  console.log(c('cyan', `▶ Scanning ${publishFiles.length} npm tarball files...`));
  publishFiles.forEach((f) => fs.existsSync(f) && scanFile(f));
} else {
  console.log(c('cyan', '▶ Scanning project files...'));
  rootFiles.forEach((entry) => {
    if (!fs.existsSync(entry)) return;
    const stat = fs.statSync(entry);
    if (stat.isFile()) return scanFile(entry);
    const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).forEach((e) => {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP_DIR.has(e.name)) walk(full);
      } else {
        scanFile(full);
      }
    });
    walk(entry);
  });
}

['HIGH', 'MEDIUM', 'LOW'].forEach((sev) => {
  const list = findings.filter((f) => f.severity === sev);
  if (!list.length) return;
  const col = sev === 'HIGH' ? 'red' : sev === 'MEDIUM' ? 'yellow' : 'dim';
  console.log(c(col, `\n[${sev}] ${list.length} finding(s):`));
  list.forEach((f) => {
    console.log(`  ${c(col, '●')} ${f.pattern}`);
    console.log(`    File : ${f.file}${f.line ? ':' + f.line : ''}`);
    console.log(`    Match: ${c('dim', f.match)}`);
  });
});

fs.writeFileSync(path.join(process.cwd(), REPORT_FILE), JSON.stringify({ timestamp: new Date().toISOString(), findings, summary: { violations, lowCount, total: findings.length } }, null, 2));
if (violations === 0) {
  console.log(c('green', `\n✓ No secrets detected${lowCount ? ` (${lowCount} low-severity warning(s))` : ''}.\n`));
  process.exit(0);
}
console.error(c('red', `\n✗ ${violations} HIGH/MEDIUM secret(s) found. Blocking publish.\n`));
process.exit(1);
