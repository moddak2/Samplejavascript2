'use strict';

const crypto = require('crypto');
const path = require('path');

function assertNonEmptyString(label, value) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
}

function escapeHtml(value) {
  const str = String(value);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function normalizeDigits(input) {
  return String(input).replace(/\D/g, '');
}

function maskCardNumber(cardNumber) {
  const digits = normalizeDigits(cardNumber);
  const last4 = digits.slice(-4).padStart(4, '*');
  return `**** **** **** ${last4}`;
}

function maskRrn(rrn) {
  const raw = String(rrn);
  const match = raw.match(/^(\d{6})-(\d{7})$/);
  if (!match) return '******-*******';
  return `${match[1]}-*******`;
}

function maskPhone(phone) {
  const raw = String(phone);
  const match = raw.match(/^(\d{2,3})-(\d{3,4})-(\d{4})$/);
  if (!match) return '***-****-****';
  return `${match[1]}-****-${match[3]}`;
}

function redactRecordForLogs(record) {
  const safe = { ...record };
  if (Object.prototype.hasOwnProperty.call(safe, 'cardNumber')) safe.cardNumber = maskCardNumber(safe.cardNumber);
  if (Object.prototype.hasOwnProperty.call(safe, 'rrn')) safe.rrn = maskRrn(safe.rrn);
  if (Object.prototype.hasOwnProperty.call(safe, 'phone')) safe.phone = maskPhone(safe.phone);
  if (Object.prototype.hasOwnProperty.call(safe, 'password')) safe.password = '[REDACTED]';
  return safe;
}

function validateExampleRecord(record) {
  if (record == null || typeof record !== 'object' || Array.isArray(record)) {
    throw new TypeError('record must be an object');
  }

  if (typeof record.name !== 'string' || record.name.length < 1 || record.name.length > 80) {
    throw new TypeError('name must be a string (1..80)');
  }

  if (typeof record.birthDate !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(record.birthDate)) {
    throw new TypeError('birthDate must be YYYY-MM-DD');
  }

  if (typeof record.phone !== 'string' || !/^\d{2,3}-\d{3,4}-\d{4}$/.test(record.phone)) {
    throw new TypeError('phone must look like 010-0000-0000');
  }

  if (typeof record.rrn !== 'string' || !/^\d{6}-\d{7}$/.test(record.rrn)) {
    throw new TypeError('rrn must look like 000000-0000000 (example format only)');
  }

  if (typeof record.cardNumber !== 'string' || normalizeDigits(record.cardNumber).length < 12) {
    throw new TypeError('cardNumber must contain at least 12 digits');
  }

  if (typeof record.note !== 'string') {
    throw new TypeError('note must be a string');
  }

  return true;
}

function deriveKeyFromPassphrase(passphrase, salt) {
  assertNonEmptyString('passphrase', passphrase);
  if (!Buffer.isBuffer(salt)) throw new TypeError('salt must be a Buffer');
  return crypto.scryptSync(passphrase, salt, 32);
}

function encryptJsonAes256Gcm(obj, passphrase) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKeyFromPassphrase(passphrase, salt);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const payload = {
    v: 1,
    kdf: 'scrypt',
    alg: 'aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    ct: ciphertext.toString('base64'),
    tag: tag.toString('base64')
  };

  return JSON.stringify(payload);
}

function decryptJsonAes256Gcm(payloadJson, passphrase) {
  assertNonEmptyString('payloadJson', payloadJson);

  let payload;
  try {
    payload = JSON.parse(payloadJson);
  } catch {
    throw new TypeError('payloadJson must be valid JSON');
  }

  if (!payload || payload.v !== 1 || payload.alg !== 'aes-256-gcm' || payload.kdf !== 'scrypt') {
    throw new TypeError('Unsupported payload format');
  }

  const salt = Buffer.from(payload.salt, 'base64');
  const iv = Buffer.from(payload.iv, 'base64');
  const ciphertext = Buffer.from(payload.ct, 'base64');
  const tag = Buffer.from(payload.tag, 'base64');
  const key = deriveKeyFromPassphrase(passphrase, salt);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

function hashPasswordScrypt(password) {
  assertNonEmptyString('password', password);
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyPasswordScrypt(password, stored) {
  assertNonEmptyString('password', password);
  assertNonEmptyString('stored', stored);

  const parts = stored.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;

  const salt = Buffer.from(parts[1], 'base64');
  const expected = Buffer.from(parts[2], 'base64');
  const actual = crypto.scryptSync(password, salt, expected.length);

  if (expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(expected, actual);
}

function buildParameterizedSelect({ table, whereField, value }) {
  const allowedTables = new Set(['users', 'payments', 'profiles']);
  const allowedFields = new Set(['id', 'email', 'userId']);

  if (!allowedTables.has(table)) throw new TypeError('table is not allowed');
  if (!allowedFields.has(whereField)) throw new TypeError('whereField is not allowed');

  // User input is never concatenated into SQL; it is passed as a parameter.
  const sql = `SELECT * FROM ${table} WHERE ${whereField} = ?;`;
  return { sql, params: [String(value)] };
}

function safeJoin(baseDir, userSuppliedPath) {
  assertNonEmptyString('baseDir', baseDir);
  assertNonEmptyString('userSuppliedPath', userSuppliedPath);

  const looksLikeWindowsPath = /^[a-zA-Z]:[\\/]/.test(baseDir) || baseDir.includes('\\');
  const pathImpl = looksLikeWindowsPath ? path.win32 : path.posix;

  const base = pathImpl.resolve(baseDir);
  const target = pathImpl.resolve(baseDir, userSuppliedPath);

  // Ensure target is inside base (prevents directory traversal).
  if (target !== base && !target.startsWith(base + pathImpl.sep)) {
    throw new Error('Path traversal attempt blocked');
  }

  return target;
}

function isAllowedUrl(urlString, { allowedHosts, allowHttp = false } = {}) {
  assertNonEmptyString('urlString', urlString);

  const url = new URL(urlString);
  if (url.username || url.password) return false;

  const protocolOk = allowHttp ? (url.protocol === 'http:' || url.protocol === 'https:') : url.protocol === 'https:';
  if (!protocolOk) return false;

  const hostOk = Array.isArray(allowedHosts) && allowedHosts.length > 0 ? allowedHosts.includes(url.hostname) : false;
  return hostOk;
}

function createCsrfToken({ sessionId, secret, now = Date.now() }) {
  assertNonEmptyString('sessionId', sessionId);
  assertNonEmptyString('secret', secret);

  const nonce = crypto.randomBytes(16).toString('base64');
  const ts = String(now);
  const data = `${sessionId}.${ts}.${nonce}`;
  const mac = crypto.createHmac('sha256', secret).update(data).digest('base64');
  return Buffer.from(`${ts}.${nonce}.${mac}`, 'utf8').toString('base64');
}

function verifyCsrfToken({ token, sessionId, secret, maxAgeMs = 10 * 60 * 1000, now = Date.now() }) {
  assertNonEmptyString('token', token);
  assertNonEmptyString('sessionId', sessionId);
  assertNonEmptyString('secret', secret);

  let decoded;
  try {
    decoded = Buffer.from(token, 'base64').toString('utf8');
  } catch {
    return false;
  }

  const parts = decoded.split('.');
  if (parts.length !== 3) return false;

  const [tsStr, nonce, macB64] = parts;
  const ts = Number(tsStr);
  if (!Number.isFinite(ts)) return false;
  if (now - ts < 0 || now - ts > maxAgeMs) return false;

  const data = `${sessionId}.${tsStr}.${nonce}`;
  const expected = crypto.createHmac('sha256', secret).update(data).digest();
  let provided;
  try {
    provided = Buffer.from(macB64, 'base64');
  } catch {
    return false;
  }

  if (provided.length !== expected.length) return false;
  return crypto.timingSafeEqual(provided, expected);
}

function createFixedWindowRateLimiter({ windowMs, maxRequests }) {
  if (!Number.isInteger(windowMs) || windowMs <= 0) throw new TypeError('windowMs must be a positive integer');
  if (!Number.isInteger(maxRequests) || maxRequests <= 0) throw new TypeError('maxRequests must be a positive integer');

  const state = new Map();

  function check(key, now = Date.now()) {
    assertNonEmptyString('key', key);

    const current = state.get(key);
    if (!current || now >= current.resetAt) {
      const next = { count: 1, resetAt: now + windowMs };
      state.set(key, next);
      return { allowed: true, remaining: maxRequests - 1, retryAfterMs: 0 };
    }

    if (current.count >= maxRequests) {
      return { allowed: false, remaining: 0, retryAfterMs: Math.max(0, current.resetAt - now) };
    }

    current.count += 1;
    return { allowed: true, remaining: maxRequests - current.count, retryAfterMs: 0 };
  }

  return { check };
}

function renderHtmlCard(record) {
  // Prevent XSS by escaping all untrusted data before HTML rendering.
  return [
    '<section>',
    `  <div>Name: ${escapeHtml(record.name)}</div>`,
    `  <div>Birth: ${escapeHtml(record.birthDate)}</div>`,
    `  <div>Phone: ${escapeHtml(record.phone)}</div>`,
    `  <div>RRN: ${escapeHtml(maskRrn(record.rrn))}</div>`,
    `  <div>Card: ${escapeHtml(maskCardNumber(record.cardNumber))}</div>`,
    `  <div>Note: ${escapeHtml(record.note)}</div>`,
    '</section>'
  ].join('\n');
}

function createExampleRecord() {
  // All fields below are synthetic placeholders (NOT real personal data).
  return {
    name: '홍길동(가명)',
    birthDate: '1900-01-01',
    phone: '010-0000-0000',
    rrn: '000000-0000000',
    cardNumber: '1234 5678 9012 3456',
    note: '<img src=x onerror=alert(1)>'
  };
}

module.exports = {
  escapeHtml,
  maskCardNumber,
  maskRrn,
  maskPhone,
  redactRecordForLogs,
  validateExampleRecord,
  encryptJsonAes256Gcm,
  decryptJsonAes256Gcm,
  hashPasswordScrypt,
  verifyPasswordScrypt,
  buildParameterizedSelect,
  safeJoin,
  isAllowedUrl,
  createCsrfToken,
  verifyCsrfToken,
  createFixedWindowRateLimiter,
  renderHtmlCard,
  createExampleRecord
};
