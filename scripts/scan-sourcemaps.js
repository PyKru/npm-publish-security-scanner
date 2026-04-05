#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const COLORS = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m'
};

const c = (color, text) => `${COLORS[color]}${text}${COLORS.reset}`;

function readJsonIfExists(file) {
  try {
    return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : null;
  } catch {
    return null;
  }
}

const allowlist = readJsonIfExists(path.join(process.cwd(), 'rules', 'allowlist.json')) || { allowedMapFiles: [] };

const CONFIG = {
  allowedMapFiles: [
    ...(allowlist.allowedMapFiles || []),
    ...(process.env.ALLOWED_MAP_FILES || '').split(',').map(v => v.trim()).filter(Boolean)
  ],
  distDirs: ['dist', 'build', 'lib', 'out', 'public'],
  inlineSourcemapRx: /\/\/[#@]\s*sourceMappingURL=data:application\/json/,
  externalMapRx: /\/\/[#@]\s*sourceMappingURL=(.+\.map)\s*$/m
};

let violations = 0;
const warnings = [];
const findings = [];

function walk(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : [full];
  });
}

function record(severity, file, reason) {
  findings.push({ severity, file, reason });
  if (severity === 'HIGH') violations += 1;
}

function checkDir(dir) {
  for (const file of walk(dir)) {
    if (file.endsWith('.map')) {
      if (CONFIG.allowedMapFiles.includes(path.basename(file))) {
        console.log(c('yellow', `  [SKIP] Allowed map file: ${file}`));
      } else {
        console.error(c('red', `  [FAIL] Source map file found: ${file}`));
        record('HIGH', file, 'Source map file present');
      }
    }

    if (/\.(js|mjs|cjs|css)$/.test(file)) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        if (CONFIG.inlineSourcemapRx.test(content)) {
          console.error(c('red', `  [FAIL] Inline base64 sourcemap in: ${file}`));
          record('HIGH', file, 'Inline sourcemap found');
        }
        const extMatch = content.match(CONFIG.externalMapRx);
        if (extMatch && !extMatch[1].startsWith('http')) {
          warnings.push(`  [WARN] External sourcemap ref in ${file} → ${extMatch[1]}`);
        }
      } catch {}
    }
  }
}

function checkNpmPack() {
  try {
    const output = execSync('npm pack --dry-run --json', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const files = JSON.parse(output)[0]?.files?.map((f) => f.path) || [];
    for (const file of files) {
      if (file.endsWith('.map')) {
        console.error(c('red', `  [FAIL] .map in npm tarball: ${file}`));
        record('HIGH', file, '.map included in tarball');
      }
    }
  } catch {
    console.log(c('yellow', '  [WARN] Could not run npm pack --dry-run'));
  }
}

console.log(c('bold', '\n🗺 Sourcemap Leak Scanner\n'));
console.log(c('cyan', '▶ Checking build output directories...'));
CONFIG.distDirs.forEach(checkDir);

console.log(c('cyan', '\n▶ Checking npm pack manifest...'));
checkNpmPack();
warnings.forEach((w) => console.log(c('yellow', w)));

fs.writeFileSync('scan-sourcemaps.report.json', JSON.stringify({ findings, warnings }, null, 2));

if (violations === 0) {
  console.log(c('green', '\n✓ No sourcemap leaks detected.\n'));
  process.exit(0);
}

console.error(c('red', `\n✗ ${violations} sourcemap violation(s). Blocking publish.\n`));
process.exit(1);
