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

describe('scan-secrets policy enforcement', () => {
  let tmpDir;
  let scannerPath;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secret-policy-'));
    fs.mkdirSync(path.join(tmpDir, 'dist'), { recursive: true });
    fs.mkdirSync(path.join(tmpDir, 'rules'), { recursive: true });
    scannerPath = copyScanner(tmpDir, path.resolve('scripts/scan-secrets.js'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('loads custom patterns and blocks matching secrets from published files', () => {
    writeJson(path.join(tmpDir, 'package.json'), {
      name: 'fixture-pkg',
      version: '1.0.0',
      files: ['dist/', 'rules/']
    });

    writeJson(path.join(tmpDir, 'rules', 'custom-patterns.json'), {
      version: '1.0',
      patterns: [
        { name: 'Internal Token', regex: 'MYCO_[A-Z0-9]{32}', severity: 'HIGH' }
      ]
    });

    writeJson(path.join(tmpDir, 'rules', 'allowlist.json'), {
      version: '1.1',
      allowedSecretPatterns: [],
      allowedMapFiles: [],
      allowedFiles: []
    });

    fs.writeFileSync(path.join(tmpDir, 'dist', 'index.js'), 'const token = "MYCO_1234567890ABCDEF1234567890ABCD";\n');

    const result = spawnSync(process.execPath, [scannerPath], { cwd: tmpDir, encoding: 'utf8' });
    expect(result.status).toBe(1);
    expect(result.stdout + result.stderr).toContain('Internal Token');

    const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'scan-secrets.report.json'), 'utf8'));
    expect(report.findings.some((f) => f.pattern === 'Internal Token')).toBe(true);
  });

  test('allowlist suppresses matching secret only in scoped published file', () => {
    writeJson(path.join(tmpDir, 'package.json'), {
      name: 'fixture-pkg',
      version: '1.0.0',
      files: ['dist/', 'README.md', 'rules/']
    });

    writeJson(path.join(tmpDir, 'rules', 'custom-patterns.json'), {
      version: '1.0',
      patterns: [
        { name: 'Internal Token', regex: 'MYCO_[A-Z0-9]{32}', severity: 'HIGH' }
      ]
    });

    writeJson(path.join(tmpDir, 'rules', 'allowlist.json'), {
      version: '1.1',
      allowedSecretPatterns: [
        {
          pattern: 'MYCO_1234567890ABCDEF1234567890ABCD',
          path: 'README.md',
          approvedBy: 'security-team',
          reason: 'doc example',
          expires: '2099-12-31'
        }
      ],
      allowedMapFiles: [],
      allowedFiles: []
    });

    fs.writeFileSync(path.join(tmpDir, 'README.md'), 'Example token MYCO_1234567890ABCDEF1234567890ABCD\n');
    fs.writeFileSync(path.join(tmpDir, 'dist', 'index.js'), 'const token = "MYCO_1234567890ABCDEF1234567890ABCD";\n');

    const result = spawnSync(process.execPath, [scannerPath], { cwd: tmpDir, encoding: 'utf8' });
    expect(result.status).toBe(1);

    const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'scan-secrets.report.json'), 'utf8'));
    expect(report.findings.some((f) => f.file === 'README.md')).toBe(false);
    expect(report.findings.some((f) => f.file === 'dist/index.js')).toBe(true);
  });

  test('expired allowlist entries do not suppress findings', () => {
    writeJson(path.join(tmpDir, 'package.json'), {
      name: 'fixture-pkg',
      version: '1.0.0',
      files: ['dist/', 'rules/']
    });

    writeJson(path.join(tmpDir, 'rules', 'custom-patterns.json'), {
      version: '1.0',
      patterns: [
        { name: 'Internal Token', regex: 'MYCO_[A-Z0-9]{32}', severity: 'HIGH' }
      ]
    });

    writeJson(path.join(tmpDir, 'rules', 'allowlist.json'), {
      version: '1.1',
      allowedSecretPatterns: [
        {
          pattern: 'MYCO_1234567890ABCDEF1234567890ABCD',
          path: 'dist/index.js',
          approvedBy: 'security-team',
          reason: 'expired exception',
          expires: '2020-01-01'
        }
      ],
      allowedMapFiles: [],
      allowedFiles: []
    });

    fs.writeFileSync(path.join(tmpDir, 'dist', 'index.js'), 'const token = "MYCO_1234567890ABCDEF1234567890ABCD";\n');

    const result = spawnSync(process.execPath, [scannerPath], { cwd: tmpDir, encoding: 'utf8' });
    expect(result.status).toBe(1);

    const report = JSON.parse(fs.readFileSync(path.join(tmpDir, 'scan-secrets.report.json'), 'utf8'));
    expect(report.findings.some((f) => f.pattern === 'Internal Token')).toBe(true);
  });
});
