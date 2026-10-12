'use strict';

// Chiffrement au repos.
// - Métadonnées (nom du fichier, déposant, message, clé du fichier) et noms des espaces :
//   AES-256-GCM avec une clé dérivée de MASTER_KEY, liée à l'objet par les données associées.
// - Contenu : une clé aléatoire par fichier, découpé en blocs de 1 Mo chiffrés chacun en
//   AES-256-GCM. Le nonce contient le numéro du bloc et les données associées marquent le dernier
//   bloc : un bloc déplacé, modifié ou une fin coupée sont détectés avant tout envoi en clair.

const crypto = require('node:crypto');

const CHUNK_SIZE = 1024 * 1024;
const TAG_LENGTH = 16;
const SEAL_VERSION = 1;

function deriveKey(masterKey, label) {
  return Buffer.from(crypto.hkdfSync('sha256', masterKey, Buffer.alloc(0), label, 32));
}

function seal(key, plaintext, context) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(context, 'utf8'));
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([Buffer.from([SEAL_VERSION]), iv, cipher.getAuthTag(), body]);
}

function open(key, blob, context) {
  if (!Buffer.isBuffer(blob) || blob.length < 29 || blob[0] !== SEAL_VERSION) {
    throw new Error('format chiffré inconnu');
  }
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(1, 13));
  decipher.setAAD(Buffer.from(context, 'utf8'));
  decipher.setAuthTag(blob.subarray(13, 29));
  return Buffer.concat([decipher.update(blob.subarray(29)), decipher.final()]);
}

function sealJson(key, value, context) {
  return seal(key, Buffer.from(JSON.stringify(value), 'utf8'), context);
}

function openJson(key, blob, context) {
  return JSON.parse(open(key, blob, context).toString('utf8'));
}

function chunkCount(size, chunkSize = CHUNK_SIZE) {
  return Math.max(1, Math.ceil(size / chunkSize));
}

function chunkLength(size, index, chunkSize = CHUNK_SIZE) {
  const count = chunkCount(size, chunkSize);
  return index < count - 1 ? chunkSize : size - chunkSize * (count - 1);
}

function chunkNonce(prefix, index) {
  const nonce = Buffer.alloc(12);
  prefix.copy(nonce, 0, 0, 8);
  nonce.writeUInt32BE(index, 8);
  return nonce;
}

function chunkAad(index, final) {
  const aad = Buffer.alloc(5);
  aad.writeUInt32BE(index, 0);
  aad[4] = final ? 1 : 0;
  return aad;
}

function encryptChunk(key, prefix, index, final, plaintext) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, chunkNonce(prefix, index));
  cipher.setAAD(chunkAad(index, final));
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function decryptChunk(key, prefix, index, final, data) {
  if (data.length < TAG_LENGTH) throw new Error('bloc tronqué');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, chunkNonce(prefix, index));
  decipher.setAAD(chunkAad(index, final));
  decipher.setAuthTag(data.subarray(data.length - TAG_LENGTH));
  return Buffer.concat([decipher.update(data.subarray(0, data.length - TAG_LENGTH)), decipher.final()]);
}

function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

function newToken() {
  return crypto.randomBytes(32).toString('base64url');
}

module.exports = {
  CHUNK_SIZE,
  TAG_LENGTH,
  deriveKey,
  seal,
  open,
  sealJson,
  openJson,
  chunkCount,
  chunkLength,
  encryptChunk,
  decryptChunk,
  sha256Hex,
  randomHex,
  newToken,
};
