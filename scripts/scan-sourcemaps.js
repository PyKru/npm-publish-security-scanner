#!/usr/bin/env node
/**
 * scan-sourcemaps.js
 * Detects leaked .map files in the publish tarball or dist folder.
 * Exit code 1 if leaks are found.
 */
const fs   = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const COLORS = {
  reset:'\x1b[0m', red:'\x1b[31m', yellow:'\x1b[33m',
  green:'\x1b[32m', cyan:'\x1b[36m', bold:'\x1b[1m',
};
const c = (color, text) => `${COLORS[color]}${text}${COLORS.reset}`;

const CONFIG = {
  allowedMapFiles:   (process.env.ALLOWED_MAP_FILES || '').split(',').filter(Boolean),
  distDirs:          ['dist', 'build', 'lib', 'out', 'public'],
  inlineSourcemapRx: /\/\/[#@]\s*sourceMappingURL=data:application\/json/,
  externalMapRx:     /\/\/[#@]\s*sourceMappingURL=(.+\.map)\s*$/m,
};

let violations = 0;
const warnings = [];

function walk(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
    const full = path.join(dir, e.name);
    return e.isDirectory() ? walk(full) : [full];
  });
}

function checkDir(dir) {
  walk(dir).forEach(file => {
    if (file.endsWith('.map')) {
      if (CONFIG.allowedMapFiles.includes(path.basename(file))) {
        console.log(c('yellow', `  [SKIP] Allowed map file: ${file}`));
        return;
      }
      console.error(c('red', `  [FAIL] Source map file found: ${file}`));
      violations++;
    }
    if (/\.(js|mjs|cjs|css)$/.test(file)) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        if (CONFIG.inlineSourcemapRx.test(content)) {
          console.error(c('red', `  [FAIL] Inline base64 sourcemap in: ${file}`));
          violations++;
        }
        const extMatch = content.match(CONFIG.externalMapRx);
        if (extMatch && !extMatch[1].startsWith('http'))
          warnings.push(`  [WARN] External sourcemap ref in ${file} → ${extMatch[1]}`);
      } catch (_) {}
    }
  });
}

function checkNpmPack() {
  try {
    const output = execSync('npm pack --dry-run --json 2>/dev/null', { encoding: 'utf8' });
    const files  = JSON.parse(output)[0]?.files?.map(f => f.path) || [];
    files.forEach(f => {
      if (f.endsWith('.map')) {
        console.error(c('red', `  [FAIL] .map in npm tarball: ${f}`));
        violations++;
      }
    });
  } catch (_) {
    console.log(c('yellow', '  [WARN] Could not run npm pack --dry-run'));
  }
}

console.log(c('bold', '\n🗺  Sourcemap Leak Scanner\n'));
console.log(c('cyan', '▶ Checking dist/build directories...'));
CONFIG.distDirs.forEach(checkDir);
console.log(c('cyan', '\n▶ Checking npm pack manifest...'));
checkNpmPack();
warnings.forEach(w => console.log(c('yellow', w)));

if (violations === 0) {
  console.log(c('green', '\n✓ No sourcemap leaks detected.\n'));
  process.exit(0);
} else {
  console.error(c('red', `\n✗ ${violations} sourcemap violation(s). Blocking publish.\n`));
  process.exit(1);
}
