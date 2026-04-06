const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

function writeJson(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function copyScanner(tmpDir, sourcePath) {
  const target = path.join(tmpDir, 'scripts', path.basename(sourcePath));
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(sourcePath, target);
  return target;
}

describe('scan-sourcemaps allowlist enforcement', () => {
  let tmpDir;
  let scannerPath;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sourcemap-policy-'));
    fs.mkdirSync(path.join(tmpDir, 'dist'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, 'rules'), { recursive: true });
    scannerPath = copyScanner(tmpDir, path.resolve('scripts/scan-sourcemaps.js'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('flags sourcemap file when not allowlisted', () => {
    writeJson(path.join(tmpDir, 'package.json'), {
      name: 'fixture-pkg',
      version: '1.0.0',
      files: ['dist/', 'rules/']
    });

    writeJson(path.join(tmpDir, 'rules', 'allowlist.json'), {
      version: '1.1',
      allowedMapFiles: [],
      allowedSecretPatterns: [],
      allowedFiles: []
    });

    fs.writeFileSync(path.join(tmpDir, 'dist', 'bundle.js.map'), '{}');

    const result = spawnSync(process.execPath, [scannerPath], { cwd: tmpDir, encoding: 'utf8' });
    expect(result.status).toBe(1);

    const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'scan-sourcemaps.report.json'), 'utf8'));
    expect(report.findings.some((f) => f.file === 'dist/bundle.js.map')).toBe(true);
  });

  test('allowlisted sourcemap file is suppressed', () => {
    writeJson(path.join(tmpDir, 'package.json'), {
      name: 'fixture-pkg',
      version: '1.0.0',
      files: ['dist/', 'rules/']
    });

    writeJson(path.join(tmpDir, 'rules', 'allowlist.json'), {
      version: '1.1',
      allowedMapFiles: ['bundle.js.map'],
      allowedSecretPatterns: [],
      allowedFiles: []
    });

    fs.writeFileSync(path.join(tmpDir, 'dist', 'bundle.js.map'), '{}');

    const result = spawnSync(process.execPath, [scannerPath], {
      cwd: tmpDir,
      encoding: 'utf8',
      env: { ...process.env, ALLOWED_MAP_FILES: 'bundle.js.map' }
    });
    expect(result.status).toBe(0);

    const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'scan-sourcemaps.report.json'), 'utf8'));
    expect(report.findings).toHaveLength(0);
  });

  test('environment variable allowlist also suppresses sourcemap file', () => {
    writeJson(path.join(tmpDir, 'package.json'), {
      name: 'fixture-pkg',
      version: '1.0.0',
      files: ['dist/', 'rules/']
    });

    writeJson(path.join(tmpDir, 'rules', 'allowlist.json'), {
      version: '1.1',
      allowedMapFiles: [],
      allowedSecretPatterns: [],
      allowedFiles: []
    });

    fs.writeFileSync(path.join(tmpDir, 'dist', 'bundle.js.map'), '{}');

    const result = spawnSync(process.execPath, [scannerPath], {
      cwd: tmpDir,
      encoding: 'utf8',
      env: { ...process.env, ALLOWED_MAP_FILES: 'bundle.js.map' }
    });
    expect(result.status).toBe(0);

    const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'scan-sourcemaps.report.json'), 'utf8'));
    expect(report.findings).toHaveLength(0);
  });
});
