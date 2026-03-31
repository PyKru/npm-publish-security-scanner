#!/usr/bin/env node
/**
 * scan-unintended-files.js
 * Detects sensitive/unintended files in the npm publish tarball.
 * Validates .npmignore and package.json "files" field alignment.
 */
const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const c = (col, t) => `\x1b[${{red:'31',yellow:'33',green:'32',cyan:'36',bold:'1',dim:'2'}[col]}m${t}\x1b[0m`;

const BLOCKED_EXACT = new Set([
  '.env','.env.local','.env.development','.env.production','.env.staging',
  '.env.test','.envrc','.bash_history','.zsh_history','.npmrc','.yarnrc',
  '.yarnrc.yml','Makefile','Dockerfile','docker-compose.yml','docker-compose.yaml',
  '.dockerignore','terraform.tfvars','serverless.yml','serverless.yaml',
  'firebase.json','netlify.toml','.sentryclirc','aws-exports.js',
  'amplify-meta.json','local.settings.json',
]);

const BLOCKED_EXTENSIONS = new Set([
  '.pem','.key','.p12','.pfx','.cer','.crt','.csr','.jks','.keystore','.pkcs8','.ppk','.p8','.asc',
]);

const BLOCKED_PATTERNS = [
  { rx:/^\.env\./,                        name:'.env variant',           severity:'HIGH' },
  { rx:/secrets?\//i,                     name:'secrets directory',      severity:'HIGH' },
  { rx:/credentials?\//i,                 name:'credentials directory',  severity:'HIGH' },
  { rx:/private\//i,                      name:'private directory',      severity:'MEDIUM' },
  { rx:/\.github\/workflows\//,           name:'CI workflow file',       severity:'LOW' },
  { rx:/coverage\//,                      name:'coverage directory',     severity:'LOW' },
  { rx:/\.(test|spec)\.(js|ts|jsx|tsx)$/, name:'test file',             severity:'LOW' },
  { rx:/__tests__\//,                     name:'__tests__ dir',          severity:'LOW' },
  { rx:/jest\.config\./,                  name:'jest config',            severity:'LOW' },
  { rx:/cypress\//,                       name:'cypress tests',          severity:'LOW' },
  { rx:/playwright\./,                    name:'playwright config',      severity:'LOW' },
  { rx:/\.husky\//,                       name:'husky hooks',            severity:'LOW' },
];

const MAX_FILE_MB  = parseFloat(process.env.MAX_FILE_MB  || '5');
const MAX_TOTAL_MB = parseFloat(process.env.MAX_TOTAL_MB || '50');

let criticalViolations = 0;
const allFindings = [];

function checkPackedFiles(files) {
  let totalBytes = 0;
  files.forEach(({ path: filePath, size }) => {
    totalBytes += (size || 0);
    const basename = path.basename(filePath);
    const ext      = path.extname(filePath).toLowerCase();
    if (BLOCKED_EXACT.has(basename)) {
      allFindings.push({ path: filePath, rule:`Blocked file: ${basename}`, severity:'HIGH' });
      criticalViolations++; return;
    }
    if (BLOCKED_EXTENSIONS.has(ext)) {
      allFindings.push({ path: filePath, rule:`Blocked extension: ${ext}`, severity:'HIGH' });
      criticalViolations++; return;
    }
    BLOCKED_PATTERNS.forEach(({ rx, name, severity }) => {
      if (rx.test(filePath)) {
        allFindings.push({ path: filePath, rule: name, severity });
        if (severity === 'HIGH') criticalViolations++;
      }
    });
    if (size && size > MAX_FILE_MB * 1024 * 1024) {
      allFindings.push({ path: filePath, rule:`File too large: ${(size/1024/1024).toFixed(2)} MB`, severity:'MEDIUM' });
    }
  });
  const totalMB = totalBytes / 1024 / 1024;
  if (totalMB > MAX_TOTAL_MB)
    allFindings.push({ path:'(package)', rule:`Package too large: ${totalMB.toFixed(2)} MB`, severity:'MEDIUM' });
  return { totalMB };
}

function validateNpmIgnore() {
  const issues = [];
  const pkg = JSON.parse(fs.readFileSync('package.json','utf8'));
  if (!fs.existsSync('.npmignore') && !pkg.files) {
    issues.push('No .npmignore AND no "files" field — ALL project files will publish!');
    criticalViolations++;
  }
  if (pkg.files?.includes('*')) {
    issues.push('"files" field contains "*" — removes allowlist protection.');
    criticalViolations++;
  }
  return issues;
}

console.log(c('bold','\n📦 Unintended Files Scanner\n'));
let packedFiles = [];
try {
  const out = execSync('npm pack --dry-run --json 2>/dev/null', { encoding:'utf8' });
  packedFiles = JSON.parse(out)[0]?.files || [];
  console.log(c('cyan',`▶ Tarball includes ${packedFiles.length} files:`));
  packedFiles.forEach(f => console.log(c('dim',`    ${f.path}  (${((f.size||0)/1024).toFixed(1)} KB)`)));
} catch (_) { console.log(c('yellow','  [WARN] Could not run npm pack --dry-run')); }

console.log(c('cyan','\n▶ Checking blocked files...'));
const { totalMB } = checkPackedFiles(packedFiles);
console.log(c('dim',`  Total size: ${totalMB.toFixed(2)} MB`));

console.log(c('cyan','\n▶ Validating .npmignore / package.json files[]...'));
try { validateNpmIgnore().forEach(i => console.error(c('red',`  [CONFIG] ${i}`))); }
catch (e) { console.log(c('yellow',`  [WARN] ${e.message}`)); }

['HIGH','MEDIUM','LOW'].forEach(sev => {
  const list = allFindings.filter(f => f.severity===sev);
  if (!list.length) return;
  const col = sev==='HIGH'?'red':sev==='MEDIUM'?'yellow':'dim';
  console.log(c(col,`\n[${sev}] ${list.length} finding(s):`));
  list.forEach(f => console.log(`  ${c(col,'●')} ${f.path}\n    ${f.rule}`));
});

if (criticalViolations === 0) {
  console.log(c('green','\n✓ No unintended files detected.\n'));
  process.exit(0);
} else {
  console.error(c('red',`\n✗ ${criticalViolations} critical file violation(s). Blocking publish.\n`));
  process.exit(1);
}
