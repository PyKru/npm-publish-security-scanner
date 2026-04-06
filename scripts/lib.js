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
  return normalizePath(path.relative(cwd, path.resolve(cwd, p)));
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
  const result = spawnSync('npm', ['pack', '--dry-run', '--json'], {
    cwd: process.cwd(),
    encoding: 'utf8',
    shell: process.platform === 'win32'
  });

  if (result.status !== 0) {
    return {
      ok: false,
      error: (result.stderr || result.stdout || 'npm pack --dry-run failed').trim(),
      files: [],
      raw: null
    };
  }

  try {
    const parsed = JSON.parse(result.stdout);
    const pkg = Array.isArray(parsed) ? parsed[0] : parsed;
    return { ok: true, files: Array.isArray(pkg?.files) ? pkg.files : [], raw: pkg };
  } catch (error) {
    return { ok: false, error: `Failed to parse npm pack output: ${error.message}`, files: [], raw: null };
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

function writeReport(reportFile, scanner, findings, extra = {}) {
  const summary = summarizeFindings(findings);
  const overall = summary.high > 0 ? 'FAIL' : 'PASS';
  const report = { schemaVersion: '2.0', scanner, timestamp: isoNow(), overall, summary, findings, ...extra };
  writeJson(reportFile, report);
  return report;
}

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
