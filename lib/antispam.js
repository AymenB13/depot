'use strict';

// Anti-abus du dépôt public : petit calcul imposé au navigateur (preuve de travail), volumes
// quotidiens plafonnés par adresse et en tout. Rien n'est écrit sur disque.

const crypto = require('node:crypto');

const CHALLENGE_MS = 10 * 60 * 1000;
const DAY_MS = 24 * 3600 * 1000;

function leadingZeroBits(buffer) {
  let bits = 0;
  for (const byte of buffer) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

class ProofOfWork {
  constructor(key, bits) {
    this.key = key;
    this.bits = bits;
    this.used = new Map();
  }

  sign(value) {
    return crypto.createHmac('sha256', this.key).update(value).digest('base64url');
  }

  issue() {
    const value = `${Date.now() + CHALLENGE_MS}.${crypto.randomBytes(16).toString('base64url')}`;
    return { challenge: `${value}.${this.sign(value)}`, bits: this.bits };
  }

  // Défi signé, pas expiré, jamais utilisé, et SHA-256(défi:nonce) commence par assez de zéros.
  verify(challenge, nonce) {
    if (typeof challenge !== 'string' || challenge.length > 200) return false;
    if (typeof nonce !== 'string' || !/^\d{1,12}$/.test(nonce)) return false;
    const cut = challenge.lastIndexOf('.');
    if (cut < 0) return false;
    const value = challenge.slice(0, cut);
    const expected = Buffer.from(this.sign(value));
    const given = Buffer.from(challenge.slice(cut + 1));
    if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) return false;
    const expires = Number(value.split('.')[0]);
    if (!Number.isFinite(expires) || expires < Date.now() || this.used.has(challenge)) return false;
    const digest = crypto.createHash('sha256').update(`${challenge}:${nonce}`).digest();
    if (leadingZeroBits(digest) < this.bits) return false;
    this.used.set(challenge, expires);
    return true;
  }

  sweep() {
    const now = Date.now();
    for (const [challenge, expires] of this.used) if (expires < now) this.used.delete(challenge);
  }
}

// Octets acceptés sur 24 heures glissantes par clé (adresse IP, ou « tout »).
class DailyVolume {
  constructor(limit) {
    this.limit = limit;
    this.entries = new Map();
  }

  take(key, bytes) {
    const now = Date.now();
    let entry = this.entries.get(key);
    if (!entry || entry.reset <= now) {
      entry = { bytes: 0, reset: now + DAY_MS };
      this.entries.set(key, entry);
    }
    if (bytes > 0 && entry.bytes + bytes > this.limit) return false;
    entry.bytes = Math.max(0, entry.bytes + bytes);
    return true;
  }

  sweep() {
    const now = Date.now();
    for (const [key, entry] of this.entries) if (entry.reset <= now) this.entries.delete(key);
  }
}

module.exports = { ProofOfWork, DailyVolume, leadingZeroBits };
