const fs = require('fs');
const path = require('path');
const os = require('os');

describe('scan-sourcemaps.js', () => {
  test('inline sourcemap regex matches', () => {
    const rx = /\/\/[#@]\s*sourceMappingURL=data:application\/json/;
    const content = '//# sourceMappingURL=data:application/json;base64,abc123==';
    expect(rx.test(content)).toBe(true);
  });

  test('external sourcemap regex matches local .map', () => {
    const rx = /\/\/[#@]\s*sourceMappingURL=(.+\.map)\s*$/m;
    const content = 'console.log("hi");\n//# sourceMappingURL=bundle.js.map';
    const m = content.match(rx);
    expect(m).not.toBeNull();
    expect(m[1]).toBe('bundle.js.map');
  });

  test('.map extension detection', () => {
    const files = ['bundle.js.map', 'styles.css.map', 'app.js'];
    const leaks = files.filter(f => f.endsWith('.map'));
    expect(leaks).toHaveLength(2);
    expect(leaks).not.toContain('app.js');
  });
});
