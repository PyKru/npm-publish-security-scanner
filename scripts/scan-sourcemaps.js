#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const COLORS = { red:'31', yellow:'33', green:'32', cyan:'36', bold:'1' };
const c = (color, text) => `\x1b[${COLORS[color]}m${text}\x1b[0m`;

function loadJson(file) { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (_) { return {}; } }
function normalize(p) { return p.replace(/\\/g, '/'); }

const allowCfg = loadJson(path.join('rules', 'allowlist.json'));
const REPORT_FILE = 'scan-sourcemaps.report.json';
const allowedMapFiles = new Set([
  ...(Array.isArray(allowCfg.allowedMapFiles) ? allowCfg.allowedMapFiles : []),
  ...(process.env.ALLOWED_MAP_FILES || '').split(',').map(s => s.trim()).filter(Boolean)
]);
const distDirs = ['dist', 'build', 'lib', 'out', 'public'];
const inlineSourcemapRx = /\/\/[#@]\s*sourceMappingURL=data:application\/json/;
const externalMapRx = /\/\/[#@]\s*sourceMappingURL=(.+\.map)\s*$/m;
const findings = [];
let violations = 0;

function allowMap(file) { return allowedMapFiles.has(path.basename(file)); }
function addFinding(file, reason) { findings.push({ file: normalize(file), reason, severity: 'HIGH' }); violations++; }
function walk(dir) { if (!fs.existsSync(dir)) return []; return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]); }

function checkDir(dir) {
  walk(dir).forEach(file => {
    if (file.endsWith('.map')) {
      if (allowMap(file)) return;
      addFinding(file, '.map included in tarball');
      return;
    }
    if (/\.(js|mjs|cjs|css)$/.test(file)) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        if (inlineSourcemapRx.test(content)) addFinding(file, 'inline sourcemap reference');
        const extMatch = content.match(externalMapRx);
        if (extMatch && extMatch[1] && !extMatch[1].startsWith('http') && !allowMap(extMatch[1])) addFinding(file, `external sourcemap reference: ${extMatch[1]}`);
      } catch (_) {}
    }
  });
}

function checkNpmPack() {
  try {
    const output = execSync('npm pack --dry-run --json 2>/dev/null', { encoding: 'utf8' });
    const files = JSON.parse(output)[0]?.files?.map(f => f.path) || [];
    files.forEach(f => {
      if (f.endsWith('.map') && !allowMap(f)) addFinding(f, '.map included in tarball');
    });
  } catch (_) {}
}

console.log(c('bold', '\n🗺 Sourcemap Leak Scanner\n'));
distDirs.forEach(checkDir);
checkNpmPack();
fs.writeFileSync(path.join(process.cwd(), REPORT_FILE), JSON.stringify({ timestamp: new Date().toISOString(), findings, summary: { violations, total: findings.length } }, null, 2));
if (violations === 0) { console.log(c('green', '\n✓ No sourcemap leaks detected.\n')); process.exit(0); }
console.error(c('red', `\n✗ ${violations} sourcemap violation(s). Blocking publish.\n`));
process.exit(1);
