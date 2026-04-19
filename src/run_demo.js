'use strict';

const {
  createExampleRecord,
  validateExampleRecord,
  redactRecordForLogs,
  renderHtmlCard,
  encryptJsonAes256Gcm,
  decryptJsonAes256Gcm,
  buildParameterizedSelect,
  safeJoin,
  isAllowedUrl,
  createCsrfToken,
  verifyCsrfToken,
  createFixedWindowRateLimiter,
  hashPasswordScrypt,
  verifyPasswordScrypt
} = require('./secure_demo');

function print(title, value) {
  process.stdout.write(`\n== ${title} ==\n`);
  process.stdout.write(typeof value === 'string' ? value + '\n' : JSON.stringify(value, null, 2) + '\n');
}

function main() {
  const record = createExampleRecord();
  validateExampleRecord(record);

  print('Original (synthetic placeholder)', record);
  print('Redacted for logs', redactRecordForLogs({ ...record, password: 'P@ssw0rd!' }));

  const html = renderHtmlCard(record);
  print('Rendered HTML (escaped)', html);

  // Quick XSS sanity checks
  const xssChecks = {
    containsRawTag: html.includes('<img') || html.includes('<script'),
    containsEscapedTag: html.includes('&lt;img') || html.includes('&lt;script')
  };
  print('XSS checks', xssChecks);

  // Encryption demo (passphrase is provided at runtime; not hardcoded secrets)
  const passphrase = 'demo-passphrase (caller-provided)';
  const encrypted = encryptJsonAes256Gcm(record, passphrase);
  const decrypted = decryptJsonAes256Gcm(encrypted, passphrase);
  print('Encrypted payload (truncated)', encrypted.slice(0, 120) + '...');
  print('Decrypt roundtrip ok', { ok: JSON.stringify(decrypted) === JSON.stringify(record) });

  // SQLi-safe query build demo
  const injected = "x' OR 1=1 --";
  const q = buildParameterizedSelect({ table: 'users', whereField: 'email', value: injected });
  print('Parameterized query object', q);
  print('SQLi check', { sqlContainsUserInput: q.sql.includes(injected) });

  // Path traversal demo
  const base = 'C:\\app\\uploads';
  print('safeJoin ok', safeJoin(base, 'images\\a.png'));
  let traversalBlocked = false;
  try {
    safeJoin(base, '..\\..\\windows\\system32');
  } catch {
    traversalBlocked = true;
  }
  print('Traversal blocked', { traversalBlocked });

  // SSRF allowlist demo
  print('SSRF allowlist', {
    ok: isAllowedUrl('https://api.example.com/v1', { allowedHosts: ['api.example.com'] }),
    blockedMetadata: isAllowedUrl('https://169.254.169.254/latest/meta-data', { allowedHosts: ['api.example.com'] })
  });

  // CSRF token demo
  const csrfSecret = 'csrf-secret-from-caller';
  const token = createCsrfToken({ sessionId: 'sess_123', secret: csrfSecret });
  print('CSRF token verifies', { ok: verifyCsrfToken({ token, sessionId: 'sess_123', secret: csrfSecret }) });

  // Rate limiter demo
  const rl = createFixedWindowRateLimiter({ windowMs: 1000, maxRequests: 2 });
  const r1 = rl.check('ip:1', 0);
  const r2 = rl.check('ip:1', 1);
  const r3 = rl.check('ip:1', 2);
  print('Rate limiter', { r1, r2, r3 });

  // Password hashing demo
  const stored = hashPasswordScrypt('correct horse battery staple');
  print('Password verify', {
    ok: verifyPasswordScrypt('correct horse battery staple', stored),
    bad: verifyPasswordScrypt('wrong', stored)
  });

  process.stdout.write('\nAll demo checks executed.\n');
}

main();
