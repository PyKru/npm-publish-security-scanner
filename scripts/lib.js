#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const Ajv = require("ajv");

const ajv = new Ajv({ allErrors: true, verbose: true });

const COLORS = { red: '31', yellow: '33', green: '32', cyan: '36', bold: '1', dim: '2' };
const SEVERITY_WEIGHT = { HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

const ALLOWLIST_SCHEMA = {
    "type": "object",
    "required": ["version"],
    "properties": {
        "version": {"type": "string", "pattern": "^[0-9.]+$"},
        "description": {"type": "string"},
        "allowedMapFiles": {"type": "array", "items": {"type": "string"}},
        "allowedSecretPatterns": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["pattern", "reason", "approvedBy", "expires"],
                "properties": {
                    "pattern": {"type": "string"},
                    "reason": {"type": "string", "minLength": 10},
                    "path": {"type": "string"},
                    "line": {"type": "integer"},
                    "approvedBy": {"type": "string", "minLength": 1},
                    "expires": {"type": "string", "pattern": "^\\d{4}-\\d{2}-\\d{2}$"}
                }
            }
        },
        "allowedFiles": {"type": "array", "items": {"type": "string"}}
    },
    "additionalProperties": false
};

const CUSTOM_PATTERNS_SCHEMA = {
    "type": "object",
    "required": ["version"],
    "properties": {
        "version": {"type": "string", "pattern": "^[0-9.]+$"},
        "description": {"type": "string"},
        "patterns": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "regex"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "regex": {"type": "string"},
                    "flags": {"type": "string", "pattern": "^[gimyus]*$"},
                    "severity": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]}
                }
            }
        }
    },
    "additionalProperties": false
};

function color(name, text) {
  return `\x1b[${COLORS[name] || '0'}m${text}\x1b[0m`;
}

function normalizePath(p) {
  return String(p || '').replace(/\\/g, '/').replace(/^\.\//, '');
}

function relPath(p, cwd = process.cwd()) {
  return no
  rmalizePath(path.relative(cwd, path.resolve(cwd, p)));
}

function readJson(file, fallback = null) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function fingerprint(parts) {
  return sha256(parts.filter(Boolean).join('|')).slice(0, 24);
}

function maskSecret(value) {
  const str = String(value || '');
  if (!str) return '';
  if (str.length <= 8) return `${str[0] || ''}***${str[str.length - 1] || ''}`;
  return `${str.slice(0, 4)}***${str.slice(-4)}`;
}

function isoNow() {
  return new Date().toISOString();
}

function parseBoolean(v, defaultValue = false) {
  if (v == null || v === '') return defaultValue;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

function parseNumber(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function isExpired(entry) {
  if (!entry || !entry.expires) return false;
  const t = Date.parse(entry.expires);
  return Number.isFinite(t) && t < Date.now();
}

function validateAllowlist(data) {
  const validate = ajv.compile(ALLOWLIST_SCHEMA);
  const valid = validate(data);
  if (!valid) {
    const errors = validate.errors || [];
    throw new Error(`Allowlist validation failed: ${errors.map(e => e.message).join("; ")}`);
  }
  return true;
}

function validateCustomPatterns(data) {
  const validate = ajv.compile(CUSTOM_PATTERNS_SCHEMA);
  const valid = validate(data);
  if (!valid) {
    const errors = validate.errors || [];
    throw new Error(`Custom patterns validation failed: ${errors.map(e => e.message).join("; ")}`);
  }
  return true;
}

function getPolicy() {
  const allowPath = path.join(process.cwd(), "rules", "allowlist.json");
  const customPath = path.join(process.cwd(), "rules", "custom-patterns.json");

  let allow = readJson(allowPath);
  if (allow) validateAllowlist(allow);

  let custom = readJson(customPath);
  if (custom) validateCustomPatterns(custom);

  return { allowlist: allow || {}, customPatterns: custom || {} };
}

function validateSeverity(value, fallback = 'HIGH') {
  const sev = String(value || fallback).toUpperCase();
  return ['HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(sev) ? sev : fallback;
}

function loadCustomSecretPatterns() {
  const { customPatterns } = getPolicy();
  const patterns = Array.isArray(customPatterns.patterns) ? customPatterns.patterns : [];
  return patterns.flatMap((entry) => {
    if (!entry || !entry.name || !entry.regex) return [];
    try {
      return [{
        name: String(entry.name),
        regex: new RegExp(entry.regex, entry.flags || 'g'),
        severity: validateSeverity(entry.severity, 'HIGH')
      }];
    } catch {
      return [];
    }
  });
}

function getPackedFiles() {
  try {
    const { execSync } = require('child_process');
    const output = execSync('npm pack --dry-run --json', { encoding: 'utf8' });
    const packs = JSON.parse(output);
    if (!Array.isArray(packs) || packs.length === 0) throw new Error('Invalid npm pack output');
    return {
      ok: true,
      files: packs[0].files.map(f => ({
        path: path.normalize(f.path).replace(/\.\.\//g, ''),  // Block traversal
        size: parseInt(f.size, 10) || 0
      })).filter(f => path.isAbsolute(f.path) === false && f.path.indexOf('\0') === -1)  // No null bytes
    };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

function matchesAllowedFile(filePath, allowedFiles) {
  const target = normalizePath(filePath);
  return (allowedFiles || []).some((entry) => {
    if (!entry || isExpired(entry)) return false;
    const candidate = typeof entry === 'string' ? entry : entry.path || entry.file || entry.pattern;
    if (!candidate) return false;
    const normalized = normalizePath(candidate);
    return target === normalized || target.endsWith(`/${normalized}`);
  });
}

function matchesAllowedSecret(filePath, rawMatch, allowedSecretPatterns) {
  const rel = normalizePath(filePath);
  return (allowedSecretPatterns || []).some((entry) => {
    if (!entry || !entry.pattern || isExpired(entry)) return false;
    if (String(entry.pattern) !== String(rawMatch)) return false;
    if (entry.path && normalizePath(entry.path) !== rel) return false;
    return true;
  });
}

function makeFinding({ scanner, severity, type, file, line = null, message, evidence = null, metadata = {} }) {
  const normalizedFile = file ? normalizePath(file) : null;
  return {
    id: fingerprint([scanner, severity, type, normalizedFile, line, message]),
    scanner,
    severity: validateSeverity(severity),
    type,
    file: normalizedFile,
    line,
    message,
    evidence,
    metadata
  };
}

function summarizeFindings(findings) {
  const summary = { total: findings.length, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) {
    const sev = String(finding.severity || '').toLowerCase();
    if (summary[sev] != null) summary[sev] += 1;
  }
  return summary;
}

function printFindings(findings) {
  for (const severity of ['HIGH', 'MEDIUM', 'LOW', 'INFO']) {
    const items = findings.filter((f) => f.severity === severity);
    if (!items.length) continue;
    const col = severity === 'HIGH' ? 'red' : severity === 'MEDIUM' ? 'yellow' : severity === 'LOW' ? 'dim' : 'cyan';
    console.log(color(col, `\n[${severity}] ${items.length} finding(s)`));
    for (const item of items) {
      console.log(` ${color(col, '●')} ${item.message}`);
      if (item.file) console.log(`   file: ${item.file}${item.line ? `:${item.line}` : ''}`);
      if (item.evidence) console.log(`   evidence: ${item.evidence}`);
    }
  }
}

function writeReport(filename, scanner, findings, metadata = {}) {
  const summary = findings.reduce((acc, f) => {
    acc[f.severity.toLowerCase()] = (acc[f.severity.toLowerCase()] || 0) + 1;
    return acc;
  }, { high: 0, medium: 0, low: 0 });

  const report = {
    scanner,
    timestamp: new Date().toISOString(),
    overall: summary.high === 0 ? 'PASS' : 'FAIL',
    summary,
    findings,
    metadata,
    scannedAt: process.cwd()
  };

  // ALWAYS write, even PASS
  fs.writeFileSync(filename, JSON.stringify(report, null, 2) + '\n');
  console.log(`${color('cyan', `📄 Report written:`)} ${filename}`);

  return report;
}

function writeAggregateReport(filename, data) {
  try {
    fs.writeFileSync(filename, JSON.stringify(data, null, 2) + '\n');
    return data;
  } catch (err) {
    console.error(color('red', `Failed to write aggregate report: ${err.message}`));
    process.exit(1);
  }
}

// Updated relPath (cross-OS safe)
function relPath(absPath) {
  let rel = path.relative(process.cwd(), absPath);
  rel = rel.replace(/^(\.\.(\/|\\)+)+/, '');  // Strip ../ chains
  return rel.replace(/\\/g, '/');  // Normalize Windows paths
}

// Update exports (add these if not present)
module.exports = {
  // ... all existing exports like color, getPolicy, etc.
  relPath,
  writeAggregateReport
};

module.exports = {
  color,
  relPath,
  normalizePath,
  readJson,
  writeJson,
  sha256,
  fingerprint,
  maskSecret,
  isoNow,
  parseBoolean,
  parseNumber,
  isExpired,
  getPolicy,
  validateSeverity,
  loadCustomSecretPatterns,
  getPackedFiles,
  matchesAllowedFile,
  matchesAllowedSecret,
  makeFinding,
  summarizeFindings,
  printFindings,
  writeReport,
  SEVERITY_WEIGHT,
  validateAllowlist,
  validateCustomPatterns
};
