'use strict';

// Mot de passe de l'espace d'administration : empreinte scrypt, jamais le mot de passe lui-même.
// Format : scrypt:N:r:p:sel:empreinte (base64url, sans « $ » pour rester sûr dans un fichier .env).

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);
const PARAMS = { N: 32768, r: 8, p: 1 };
const MAXMEM = 128 * 1024 * 1024;
const MIN_LENGTH = 12;

function hashPassword(password) {
  if (typeof password !== 'string' || password.length < MIN_LENGTH) {
    throw new Error(`Le mot de passe doit faire au moins ${MIN_LENGTH} caractères.`);
  }
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password.normalize('NFC'), salt, 32, { ...PARAMS, maxmem: MAXMEM });
  return ['scrypt', PARAMS.N, PARAMS.r, PARAMS.p, salt.toString('base64url'), hash.toString('base64url')].join(':');
}

async function verifyPassword(password, stored) {
  if (typeof password !== 'string' || password.length === 0 || password.length > 1024) return false;
  const parts = String(stored).split(':');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [N, r, p] = parts.slice(1, 4).map(Number);
  const salt = Buffer.from(parts[4], 'base64url');
  const expected = Buffer.from(parts[5], 'base64url');
  const actual = await scrypt(password.normalize('NFC'), salt, expected.length, { N, r, p, maxmem: MAXMEM });
  return crypto.timingSafeEqual(actual, expected);
}

module.exports = { hashPassword, verifyPassword, MIN_LENGTH };
