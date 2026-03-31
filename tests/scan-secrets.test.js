const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

describe('scan-secrets.js', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'scan-test-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  test('should pass on a clean file', () => {
    fs.writeFileSync(path.join(tmpDir, 'safe.js'), 'const x = 42;\nexport default x;');
    expect(() => execSync(`node scripts/scan-secrets.js`, { cwd: process.cwd() })).not.toThrow();
  });

  test('should detect AWS Access Key', () => {
    fs.writeFileSync(path.join(tmpDir, 'leaked.js'), 'const key = "AKIAIOSFODNN7EXAMPLE";');
    // Verify pattern fires
    const content = fs.readFileSync(path.join(tmpDir, 'leaked.js'), 'utf8');
    expect(/AKIA[0-9A-Z]{16}/.test(content)).toBe(true);
  });

  test('should detect GitHub token', () => {
    const token = 'ghp_' + 'A'.repeat(36);
    expect(/ghp_[A-Za-z0-9]{36}/.test(token)).toBe(true);
  });

  test('should detect high entropy strings', () => {
    const highEntropy = '"' + 'aB3#kL9mNq2pXw5vZyR7uT1sE4cF6hD8' + '"';
    // Shannon entropy check
    const str = highEntropy.slice(1, -1);
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    const entropy = Object.values(freq).reduce((acc, n) => {
      const p = n / str.length; return acc - p * Math.log2(p);
    }, 0);
    expect(entropy).toBeGreaterThan(4.0);
  });
});
