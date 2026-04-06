const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

function writeJson(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

describe('scan-secrets self-scan regression', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'self-scan-fix-'));
    fs.mkdirSync(path.join(tmpDir, 'scripts'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, 'rules'), { recursive: true });

    fs.copyFileSync(path.resolve('scripts/scan-secrets.js'), path.join(tmpDir, 'scripts', 'scan-secrets.js'));

    writeJson(path.join(tmpDir, 'package.json'), {
      name: 'fixture-pkg',
      version: '1.0.0',
      files: ['scripts/', 'rules/']
    });

    writeJson(path.join(tmpDir, 'rules', 'allowlist.json'), {
      version: '1.1',
      allowedSecretPatterns: [],
      allowedMapFiles: [],
      allowedFiles: []
    });

    writeJson(path.join(tmpDir, 'rules', 'custom-patterns.json'), {
      version: '1.0',
      patterns: []
    });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('does not flag built-in private key regex literals from its own source file', () => {
    const result = spawnSync(process.execPath, [path.join(tmpDir, 'scripts', 'scan-secrets.js')], {
      cwd: tmpDir,
      encoding: 'utf8'
    });

    expect(result.status).toBe(0);

    const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'scan-secrets.report.json'), 'utf8'));
    expect(report.findings).toHaveLength(0);
    expect(result.stdout + result.stderr).not.toContain('EC Private Key');
    expect(result.stdout + result.stderr).not.toContain('PGP Private Key');
  });
});
