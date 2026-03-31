#!/usr/bin/env node
/**
 * scan-dependencies.js
 * Runs npm audit, checks typosquatting, lockfile version, and dev-in-prod.
 */
const { execSync } = require('child_process');
const fs   = require('fs');

const c = (col, t) => `\x1b[${{red:'31',yellow:'33',green:'32',cyan:'36',bold:'1',dim:'2'}[col]}m${t}\x1b[0m`;

const TYPOSQUAT_PATTERNS = [
  /^lod[a4]sh$/,/^1odash$/,/^expr[e3]ss$/,/^expresss$/,/^re[4a]ct$/,
  /^reakt$/,/^event-str[e3]am$/,/^cross-[e3]nv$/,/^c[0o]lors$/,/^node-fetch-[0-9]+$/,
];

const DEV_ONLY = new Set([
  'jest','mocha','chai','sinon','nyc','istanbul','ts-jest','eslint',
  'prettier','husky','lint-staged','nodemon','ts-node',
  'webpack','rollup','vite','esbuild','parcel','cypress','playwright','puppeteer',
  'storybook','@storybook/react','@testing-library/react',
]);

const AUDIT_LEVEL = process.env.AUDIT_LEVEL || 'high';
let violations = 0;

console.log(c('bold','\n🔍 Dependency Security Scanner\n'));
console.log(c('cyan',`▶ Running npm audit (level: ${AUDIT_LEVEL})...`));

try {
  execSync(`npm audit --audit-level=${AUDIT_LEVEL} --json 2>/dev/null`, { encoding:'utf8' });
  console.log(c('green','  ✓ npm audit passed'));
} catch (e) {
  try {
    const report = JSON.parse(e.stdout || '{}');
    const { critical=0, high=0, moderate=0, low=0 } = report.metadata?.vulnerabilities || {};
    if (critical) console.error(c('red',    `  ✗ Critical: ${critical}`));
    if (high)     console.error(c('red',    `  ✗ High    : ${high}`));
    if (moderate) console.log(c('yellow',   `  ⚠ Moderate: ${moderate}`));
    if (low)      console.log(c('dim',      `    Low     : ${low}`));
    if (critical > 0 || high > 0) violations++;
  } catch (_) { console.error(c('yellow','  [WARN] Could not parse audit output')); }
}

console.log(c('cyan','\n▶ Validating lockfile...'));
if (!fs.existsSync('package-lock.json') && !fs.existsSync('yarn.lock') && !fs.existsSync('pnpm-lock.yaml')) {
  console.error(c('red','  ✗ No lockfile found — supply chain integrity impossible!')); violations++;
} else if (fs.existsSync('package-lock.json')) {
  const lock = JSON.parse(fs.readFileSync('package-lock.json','utf8'));
  if (lock.lockfileVersion < 2)
    console.log(c('yellow','  ⚠ v1 lockfile uses SHA-1 — upgrade to npm v7+ for SHA-512'));
  else console.log(c('green',`  ✓ package-lock.json v${lock.lockfileVersion} (SHA-512 integrity)`));
}

console.log(c('cyan','\n▶ Checking for typosquatted packages...'));
const pkg = JSON.parse(fs.readFileSync('package.json','utf8'));
const allDeps = { ...(pkg.dependencies||{}), ...(pkg.devDependencies||{}), ...(pkg.peerDependencies||{}) };
Object.keys(allDeps).forEach(name => {
  TYPOSQUAT_PATTERNS.forEach(rx => {
    if (rx.test(name)) { console.error(c('red',`  ✗ Possible typosquat: "${name}"`)); violations++; }
  });
});
console.log(c('dim',`  Checked ${Object.keys(allDeps).length} packages`));

console.log(c('cyan','\n▶ Checking dev-only packages in production dependencies...'));
Object.keys(pkg.dependencies||{}).forEach(name => {
  if (DEV_ONLY.has(name))
    console.log(c('yellow',`  ⚠ Dev tool in "dependencies": "${name}" — move to devDependencies`));
});

console.log(c('cyan','\n▶ Checking version pinning...'));
let unpinned = 0;
Object.entries(pkg.dependencies||{}).forEach(([name, ver]) => {
  if (/^[\^~]/.test(ver)) {
    unpinned++;
    if (unpinned <= 3) console.log(c('dim',`    Unpinned: ${name}@${ver}`));
  }
});
if (unpinned > 3) console.log(c('dim',`    ...and ${unpinned-3} more`));
if (unpinned) console.log(c('yellow',`  ⚠ ${unpinned} unpinned prod dep(s) — consider exact versions`));

if (violations === 0) { console.log(c('green','\n✓ Dependency checks passed.\n')); process.exit(0); }
else { console.error(c('red',`\n✗ ${violations} violation(s) found.\n`)); process.exit(1); }
