'use strict';

// Configuration lue dans l'environnement (voir deploy/compose.yaml et /opt/depot/app.env).

const GIB = 1024 ** 3;

function number(env, name, fallback) {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) throw new Error(`${name} invalide : ${raw}`);
  return value;
}

function loadConfig(env = process.env) {
  const masterKey = Buffer.from(env.MASTER_KEY || '', 'base64url');
  if (masterKey.length !== 32) {
    throw new Error('MASTER_KEY manquante ou invalide (32 octets en base64url)');
  }
  const adminPasswordHash = env.ADMIN_PASSWORD_HASH || '';
  if (!/^scrypt:\d+:\d+:\d+:[A-Za-z0-9_-]{16,}:[A-Za-z0-9_-]{32,}$/.test(adminPasswordHash)) {
    throw new Error('ADMIN_PASSWORD_HASH manquant ou invalide');
  }
  const publicUrl = new URL(env.PUBLIC_URL || 'https://files.aymenbenali.com');
  return Object.freeze({
    port: number(env, 'PORT', 8080),
    dataDir: env.DATA_DIR || '/data',
    masterKey,
    adminPasswordHash,
    publicOrigin: publicUrl.origin,
    retentionDays: number(env, 'RETENTION_DAYS', 90),
    maxFileBytes: number(env, 'MAX_FILE_BYTES', 2 * GIB),
    // Anti-abus : volume total gardé, volume reçu par jour (par adresse et en tout).
    storageQuotaBytes: number(env, 'STORAGE_QUOTA_BYTES', 60 * GIB),
    dailyBytesPerIp: number(env, 'DAILY_BYTES_PER_IP', 6 * GIB),
    dailyBytesTotal: number(env, 'DAILY_BYTES_TOTAL', 30 * GIB),
    // Le portail refuse un dépôt qui laisserait moins que cet espace libre sur le disque du VPS.
    minFreeBytes: number(env, 'MIN_FREE_BYTES', 20 * GIB),
    // Petit calcul demandé au navigateur avant chaque envoi (bits nuls en tête d'un SHA-256).
    powBits: number(env, 'POW_BITS', 18),
    // Antivirus ClamAV (conteneur depot-clamav). Vide : pas d'analyse, fichiers non téléchargeables.
    clamavHost: env.CLAMAV_HOST === undefined ? 'clamav' : env.CLAMAV_HOST,
    clamavPort: number(env, 'CLAMAV_PORT', 3310),
    // Cookies « Secure » partout, sauf pour les tests en local (http).
    secureCookies: env.INSECURE_COOKIES !== '1',
  });
}

module.exports = { loadConfig, GIB };
