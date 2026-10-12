'use strict';

// Sessions de l'espace d'administration (en mémoire) et limites de débit par adresse IP.

const crypto = require('node:crypto');

class Sessions {
  constructor({ ttlMs = 12 * 3600e3, idleMs = 2 * 3600e3 } = {}) {
    this.ttlMs = ttlMs;
    this.idleMs = idleMs;
    this.map = new Map();
  }

  create() {
    const id = crypto.randomBytes(32).toString('base64url');
    const now = Date.now();
    const session = { csrf: crypto.randomBytes(24).toString('base64url'), created: now, seen: now };
    this.map.set(id, session);
    return { id, ...session };
  }

  get(id) {
    if (typeof id !== 'string' || id.length !== 43) return null;
    const session = this.map.get(id);
    if (!session) return null;
    const now = Date.now();
    if (now - session.created > this.ttlMs || now - session.seen > this.idleMs) {
      this.map.delete(id);
      return null;
    }
    session.seen = now;
    return session;
  }

  destroy(id) {
    this.map.delete(id);
  }

  clear() {
    this.map.clear();
  }

  sweep() {
    for (const id of [...this.map.keys()]) this.get(id);
  }
}

const MAX_KEYS = 20000;

class RateLimiter {
  constructor(limit, windowMs) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.hits = new Map();
  }

  // Compte une tentative ; false si la limite est atteinte pour cette fenêtre.
  hit(key) {
    const now = Date.now();
    let entry = this.hits.get(key);
    if (!entry || entry.reset <= now) {
      // Mémoire bornée : au-delà de MAX_KEYS adresses suivies, les nouvelles ne sont plus comptées.
      if (!entry && this.hits.size >= MAX_KEYS) {
        this.sweep();
        if (this.hits.size >= MAX_KEYS) return true;
      }
      entry = { count: 0, reset: now + this.windowMs };
      this.hits.set(key, entry);
    }
    entry.count += 1;
    return entry.count <= this.limit;
  }

  blocked(key) {
    const entry = this.hits.get(key);
    return Boolean(entry && entry.reset > Date.now() && entry.count >= this.limit);
  }

  sweep() {
    const now = Date.now();
    for (const [key, entry] of this.hits) if (entry.reset <= now) this.hits.delete(key);
  }
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

module.exports = { Sessions, RateLimiter, safeEqual };
