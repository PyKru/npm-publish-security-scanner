#!/usr/bin/env node
/**
 * scan-secrets.js
 * Scans publish files for hardcoded secrets using pattern matching + entropy.
 * Exit code 1 on HIGH/MEDIUM findings.
 */
const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const c = (col, t) => `\x1b[${
  {red:'31',yellow:'33',green:'32',cyan:'36',bold:'1',dim:'2'}[col]
}m${t}\x1b[0m`;

const SECRET_PATTERNS = [
  { name:'AWS Access Key',          rx:/\bAKIA[0-9A-Z]{16}\b/,                        severity:'HIGH' },
  { name:'AWS Secret Key',          rx:/aws[_\-\s]?secret[_\-\s]?key\s*[:=]\s*["']?[A-Za-z0-9\/+=]{40}/i, severity:'HIGH' },
  { name:'GitHub Token (classic)',  rx:/ghp_[A-Za-z0-9]{36}/,                         severity:'HIGH' },
  { name:'GitHub Actions Token',    rx:/ghs_[A-Za-z0-9]{36}/,                         severity:'HIGH' },
  { name:'GitHub Fine-grained PAT', rx:/github_pat_[A-Za-z0-9_]{82}/,                 severity:'HIGH' },
  { name:'npm Auth Token',          rx:/\/\/registry\.npmjs\.org\/:_authToken\s*=\s*[A-Za-z0-9\-_\.]+/i, severity:'HIGH' },
  { name:'npm Token',               rx:/\bnpm_[A-Za-z0-9]{36}\b/,                     severity:'HIGH' },
  { name:'Stripe Secret Key',       rx:/sk_live_[0-9a-zA-Z]{24,}/,                    severity:'HIGH' },
  { name:'SendGrid API Key',        rx:/SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/, severity:'HIGH' },
  { name:'Slack Bot Token',         rx:/xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}/,   severity:'HIGH' },
  { name:'OpenAI API Key',          rx:/sk-[A-Za-z0-9]{48}/,                          severity:'HIGH' },
  { name:'Google API Key',          rx:/AIza[0-9A-Za-z\-_]{35}/,                      severity:'HIGH' },
  { name:'Google Service Account',  rx:/"type"\s*:\s*"service_account"/,              severity:'HIGH' },
  { name:'Firebase Config',         rx:/apiKey\s*:\s*["'][A-Za-z0-9\-_]{39}["']/i,   severity:'MEDIUM' },
  { name:'JWT Token',               rx:/eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+\/=]+/, severity:'MEDIUM' },
  { name:'RSA Private Key',         rx:/-----BEGIN (?:RSA )?PRIVATE KEY-----/,        severity:'HIGH' },
  { name:'EC Private Key',          rx:/-----BEGIN EC PRIVATE KEY-----/,              severity:'HIGH' },
  { name:'PGP Private Key',         rx:/-----BEGIN PGP PRIVATE KEY BLOCK-----/,       severity:'HIGH' },
  { name:'Generic Password',        rx:/(?:password|passwd|pwd|secret)\s*[:=]\s*["'][^"']{8,}["']/i, severity:'LOW' },
  { name:'Generic API Key',         rx:/(?:api[_\-]?key|api[_\-]?secret)\s*[:=]\s*["'][A-Za-z0-9\-_\.]{16,}["']/i, severity:'LOW' },
  { name:'.env file',               rx:/^\.env(?:\.[a-z]+)?$/i,  severity:'HIGH', filenameOnly:true },
];

function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  return Object.values(freq).reduce((acc, n) => {
    const p = n / str.length;
    return acc - p * Math.log2(p);
  }, 0);
}

const HIGH_ENTROPY_RX  = /['"][A-Za-z0-9+\/=!@#$%^&*\-_]{20,}['"]/g;
const ENTROPY_THRESHOLD = 4.5;
const SKIP_EXT = new Set(['.png','.jpg','.gif','.svg','.woff','.woff2','.ttf','.ico','.map']);
const SKIP_DIR = new Set(['node_modules','.git','coverage','__tests__','fixtures']);

let violations = 0, lowCount = 0;
const findings = [];

function scanFile(filePath) {
  const parts = filePath.split(path.sep);
  if (parts.some(p => SKIP_DIR.has(p))) return;
  if (SKIP_EXT.has(path.extname(filePath).toLowerCase())) return;

  const basename = path.basename(filePath);
  SECRET_PATTERNS.filter(p => p.filenameOnly).forEach(p => {
    if (p.rx.test(basename)) {
      findings.push({ file: filePath, line: 0, pattern: p.name, severity: p.severity, match: basename });
      p.severity === 'HIGH' ? violations++ : lowCount++;
    }
  });

  let content;
  try { content = fs.readFileSync(filePath, 'utf8'); } catch (_) { return; }
  content.split('\n').forEach((line, i) => {
    SECRET_PATTERNS.filter(p => !p.filenameOnly).forEach(p => {
      if (p.rx.test(line)) {
        const match = (line.match(p.rx)||[''])[0].slice(0, 60);
        findings.push({ file: filePath, line: i+1, pattern: p.name, severity: p.severity, match });
        (p.severity==='HIGH'||p.severity==='MEDIUM') ? violations++ : lowCount++;
      }
    });
    (line.match(HIGH_ENTROPY_RX)||[]).forEach(cand => {
      if (shannonEntropy(cand.slice(1,-1)) > ENTROPY_THRESHOLD) {
        findings.push({ file: filePath, line: i+1, pattern:'High-Entropy String', severity:'MEDIUM', match: cand.slice(0,40) });
        violations++;
      }
    });
  });
}

console.log(c('bold','\n🔐 Secret Scanner\n'));
// Get publish file list
let publishFiles = [];
try {
  const out = execSync('npm pack --dry-run --json 2>/dev/null', { encoding:'utf8' });
  publishFiles = JSON.parse(out)[0]?.files?.map(f => f.path) || [];
} catch (_) {}

if (publishFiles.length > 0) {
  console.log(c('cyan', `▶ Scanning ${publishFiles.length} npm tarball files...`));
  publishFiles.forEach(f => { if (fs.existsSync(f)) scanFile(f); });
} else {
  console.log(c('cyan','▶ Scanning project files...'));
  ['src','lib','dist','scripts'].forEach(d => {
    if (!fs.existsSync(d)) return;
    const walk = dir => fs.readdirSync(dir,{withFileTypes:true}).forEach(e => {
      const full = path.join(dir,e.name);
      e.isDirectory() && !SKIP_DIR.has(e.name) ? walk(full) : scanFile(full);
    });
    walk(d);
  });
}

['HIGH','MEDIUM','LOW'].forEach(sev => {
  const list = findings.filter(f => f.severity === sev);
  if (!list.length) return;
  const col = sev==='HIGH'?'red':sev==='MEDIUM'?'yellow':'dim';
  console.log(c(col,`\n[${sev}] ${list.length} finding(s):`));
  list.forEach(f => {
    console.log(`  ${c(col,'●')} ${f.pattern}`);
    console.log(`    File : ${f.file}${f.line?':'+f.line:''}`);
    console.log(`    Match: ${c('dim', f.match)}`);
  });
});

if (violations === 0) {
  console.log(c('green',`\n✓ No secrets detected${lowCount?` (${lowCount} low-severity warning(s))`:''}.\n`));
  process.exit(0);
} else {
  console.error(c('red',`\n✗ ${violations} HIGH/MEDIUM secret(s) found. Blocking publish.\n`));
  process.exit(1);
}
