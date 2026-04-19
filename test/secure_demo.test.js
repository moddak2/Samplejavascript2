'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  escapeHtml,
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
} = require('../src/secure_demo');

test('example record validates and renders safely (XSS escaped)', () => {
  const record = createExampleRecord();
  assert.equal(validateExampleRecord(record), true);

  const html = renderHtmlCard(record);
  assert.ok(html.includes('&lt;img'));
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('onerror="'));
  assert.ok(!html.includes('onerror=\''));
});

test('redaction removes sensitive values from logs', () => {
  const record = createExampleRecord();
  const redacted = redactRecordForLogs({ ...record, password: 'not-a-secret' });

  assert.notEqual(redacted.rrn, record.rrn);
  assert.notEqual(redacted.cardNumber, record.cardNumber);
  assert.equal(redacted.password, '[REDACTED]');
});

test('AES-256-GCM encrypt/decrypt roundtrip', () => {
  const passphrase = 'demo-passphrase (not stored)';
  const original = { a: 1, nested: { ok: true }, rrn: '000000-0000000' };

  const encrypted = encryptJsonAes256Gcm(original, passphrase);
  assert.equal(typeof encrypted, 'string');
  assert.ok(!encrypted.includes('000000-0000000'));

  const decrypted = decryptJsonAes256Gcm(encrypted, passphrase);
  assert.deepEqual(decrypted, original);
});

test('password hashing uses scrypt and verifies in constant-time', () => {
  const stored = hashPasswordScrypt('correct horse battery staple');
  assert.ok(stored.startsWith('scrypt$'));

  assert.equal(verifyPasswordScrypt('correct horse battery staple', stored), true);
  assert.equal(verifyPasswordScrypt('wrong password', stored), false);
});

test('SQL injection defense: parameterized query keeps user input out of SQL text', () => {
  const injected = "x' OR 1=1 --";
  const { sql, params } = buildParameterizedSelect({ table: 'users', whereField: 'email', value: injected });

  assert.ok(sql.includes('WHERE email = ?'));
  assert.ok(!sql.includes(injected));
  assert.deepEqual(params, [injected]);
});

test('path traversal defense: safeJoin blocks escaping the base directory', () => {
  const base = 'C:\\app\\uploads';

  assert.ok(safeJoin(base, 'images\\a.png').startsWith('C:\\app\\uploads'));

  assert.throws(() => safeJoin(base, '..\\..\\windows\\system32'), /blocked/i);
  assert.throws(() => safeJoin(base, '../..//etc/passwd'), /blocked/i);
});

test('SSRF defense: allowlist-only URL validation', () => {
  assert.equal(isAllowedUrl('https://api.example.com/v1', { allowedHosts: ['api.example.com'] }), true);
  assert.equal(isAllowedUrl('http://api.example.com/v1', { allowedHosts: ['api.example.com'] }), false);
  assert.equal(isAllowedUrl('https://169.254.169.254/latest/meta-data', { allowedHosts: ['api.example.com'] }), false);
  assert.equal(isAllowedUrl('https://api.example.com@evil.com/', { allowedHosts: ['api.example.com'] }), false);
});

test('CSRF token HMAC verifies and tampering is detected', () => {
  const sessionId = 'sess_123';
  const secret = 'csrf-secret-from-caller';
  const now = 10_000;

  const token = createCsrfToken({ sessionId, secret, now });
  assert.equal(verifyCsrfToken({ token, sessionId, secret, now, maxAgeMs: 60_000 }), true);

  // Tamper: change one char in base64 token
  const tampered = token.slice(0, -2) + (token.slice(-2, -1) === 'A' ? 'B' : 'A') + token.slice(-1);
  assert.equal(verifyCsrfToken({ token: tampered, sessionId, secret, now, maxAgeMs: 60_000 }), false);
});

test('rate limiter blocks after max requests within window', () => {
  const rl = createFixedWindowRateLimiter({ windowMs: 1000, maxRequests: 2 });

  const r1 = rl.check('ip:1', 0);
  const r2 = rl.check('ip:1', 1);
  const r3 = rl.check('ip:1', 2);

  assert.equal(r1.allowed, true);
  assert.equal(r2.allowed, true);
  assert.equal(r3.allowed, false);
  assert.ok(r3.retryAfterMs > 0);
});

test('escapeHtml escapes key characters', () => {
  const s = `<script>alert('x') & \"y\"</script>`;
  const escaped = escapeHtml(s);
  assert.ok(escaped.includes('&lt;script&gt;'));
  assert.ok(escaped.includes('&#39;x&#39;'));
  assert.ok(escaped.includes('&amp;'));
  assert.ok(escaped.includes('&quot;y&quot;'));
});
