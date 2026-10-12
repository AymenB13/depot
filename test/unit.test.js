'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  CHUNK_SIZE,
  seal,
  open,
  chunkCount,
  chunkLength,
  encryptChunk,
  decryptChunk,
} = require('../lib/crypto');
const { cleanFileName, cleanText, allowedExtension, contentDisposition } = require('../lib/names');
const { hashPassword, verifyPassword } = require('../lib/password');
const { RateLimiter, Sessions } = require('../lib/guards');
const { loadConfig } = require('../lib/config');

test('seal/open : aller-retour, contexte lié, altération détectée', () => {
  const key = crypto.randomBytes(32);
  const blob = seal(key, Buffer.from('secret'), 'meta:a');
  assert.equal(open(key, blob, 'meta:a').toString(), 'secret');
  assert.throws(() => open(key, blob, 'meta:b'));
  const tampered = Buffer.from(blob);
  tampered[tampered.length - 1] ^= 1;
  assert.throws(() => open(key, tampered, 'meta:a'));
});

test('blocs : découpage, ordre et dernier bloc protégés', () => {
  assert.equal(chunkCount(1), 1);
  assert.equal(chunkCount(CHUNK_SIZE), 1);
  assert.equal(chunkCount(CHUNK_SIZE + 1), 2);
  assert.equal(chunkLength(CHUNK_SIZE + 1, 0), CHUNK_SIZE);
  assert.equal(chunkLength(CHUNK_SIZE + 1, 1), 1);

  const key = crypto.randomBytes(32);
  const prefix = crypto.randomBytes(8);
  const plain = crypto.randomBytes(1000);
  const sealed = encryptChunk(key, prefix, 3, false, plain);
  assert.deepEqual(decryptChunk(key, prefix, 3, false, sealed), plain);
  assert.throws(() => decryptChunk(key, prefix, 4, false, sealed), 'bloc déplacé');
  assert.throws(() => decryptChunk(key, prefix, 3, true, sealed), 'faux dernier bloc');
  const tampered = Buffer.from(sealed);
  tampered[10] ^= 1;
  assert.throws(() => decryptChunk(key, prefix, 3, false, tampered), 'bloc modifié');
});

test('noms de fichiers : chemins, caractères cachés, extensions', () => {
  assert.equal(cleanFileName('C:\\Users\\z\\CA 2025.xlsx'), 'CA 2025.xlsx');
  assert.equal(cleanFileName('../../etc/passwd'), 'passwd');
  assert.equal(cleanFileName('facture\u202Efdp.exe'), 'facturefdp.exe');
  assert.equal(cleanFileName('...cache.pdf'), 'cache.pdf');
  assert.equal(cleanFileName(42), '');
  const long = `${'a'.repeat(300)}.xlsx`;
  assert.equal(cleanFileName(long).length, 180);
  assert.ok(cleanFileName(long).endsWith('.xlsx'));
  assert.ok(allowedExtension('ventes.XLSX'));
  assert.ok(!allowedExtension('script.js'));
  assert.ok(!allowedExtension('page.html'));
  assert.ok(!allowedExtension('image.svg'));
  assert.ok(!allowedExtension('sans-extension'));
  assert.equal(cleanText('  bonjour\r\nà vous \u0007', 50), 'bonjour\nà vous');
  assert.match(contentDisposition('Ventes été "2025".xlsx'), /filename="Ventes ete _2025_.xlsx"; filename\*=UTF-8''Ventes%20%C3%A9t%C3%A9%20%222025%22.xlsx/);
});

test('mot de passe : empreinte scrypt vérifiable, refus du mauvais', async () => {
  const stored = hashPassword('correct horse battery');
  assert.match(stored, /^scrypt:32768:8:1:/);
  assert.equal(await verifyPassword('correct horse battery', stored), true);
  assert.equal(await verifyPassword('correct horse batterie', stored), false);
  assert.equal(await verifyPassword('', stored), false);
  assert.throws(() => hashPassword('court'));
});

test('limites de débit et sessions', () => {
  const limiter = new RateLimiter(2, 60e3);
  assert.equal(limiter.hit('ip'), true);
  assert.equal(limiter.hit('ip'), true);
  assert.equal(limiter.hit('ip'), false);
  assert.equal(limiter.blocked('ip'), true);
  assert.equal(limiter.hit('autre'), true);

  const sessions = new Sessions({ ttlMs: 1000, idleMs: 1000 });
  const { id } = sessions.create();
  assert.ok(sessions.get(id));
  assert.equal(sessions.get('inconnu'), null);
  sessions.destroy(id);
  assert.equal(sessions.get(id), null);
});

test('configuration : clés obligatoires', () => {
  assert.throws(() => loadConfig({}), /MASTER_KEY/);
  assert.throws(() => loadConfig({ MASTER_KEY: crypto.randomBytes(32).toString('base64url') }), /ADMIN_PASSWORD_HASH/);
  const config = loadConfig({
    MASTER_KEY: crypto.randomBytes(32).toString('base64url'),
    ADMIN_PASSWORD_HASH: hashPassword('correct horse battery'),
  });
  assert.equal(config.publicOrigin, 'https://files.aymenbenali.com');
  assert.equal(config.secureCookies, true);
});

test('preuve de travail : signée, à usage unique, assez de zéros', () => {
  const { ProofOfWork, DailyVolume, leadingZeroBits } = require('../lib/antispam');
  assert.equal(leadingZeroBits(Buffer.from([0, 0x0f, 0xff])), 12);
  const pow = new ProofOfWork(crypto.randomBytes(32), 8);
  const { challenge, bits } = pow.issue();
  let nonce = 0;
  while (leadingZeroBits(crypto.createHash('sha256').update(`${challenge}:${nonce}`).digest()) < bits) nonce += 1;
  assert.equal(pow.verify(`${challenge}x`, String(nonce)), false, 'signature modifiée');
  assert.equal(pow.verify(challenge, 'abc'), false);
  assert.equal(pow.verify(challenge, String(nonce)), true);
  assert.equal(pow.verify(challenge, String(nonce)), false, 'rejeu');
  const other = new ProofOfWork(crypto.randomBytes(32), 8);
  assert.equal(other.verify(pow.issue().challenge, '1'), false, 'autre clé');

  const volume = new DailyVolume(100);
  assert.equal(volume.take('ip', 60), true);
  assert.equal(volume.take('ip', 60), false);
  assert.equal(volume.take('ip', -60), true);
  assert.equal(volume.take('ip', 60), true);
});
