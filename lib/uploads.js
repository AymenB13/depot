'use strict';

// Envois en cours. Le navigateur envoie chaque fichier en blocs de 1 Mo, dans l'ordre : une requête
// courte par bloc, qui passe le délai de 60 s du proxy même sur une connexion lente.
// Chaque bloc est chiffré dès réception et écrit à sa place ; rien n'est gardé en clair.

const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { CHUNK_SIZE, TAG_LENGTH, chunkCount, chunkLength, encryptChunk, randomHex } = require('./crypto');
const { cleanFileName, cleanText, allowedExtension, extOf } = require('./names');

const MAX_SESSIONS = 24;
const MAX_SESSIONS_PER_BOX = 6;
const MAX_CHUNKS_IN_FLIGHT = 8;
const IDLE_MS = 60 * 60 * 1000;
const RECEIPT_MS = 15 * 60 * 1000;

class UploadError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

function formatGo(bytes) {
  return `${Math.round((bytes / 1024 ** 3) * 10) / 10} Go`.replace('.', ',');
}

class Uploads {
  constructor({ store, config, log }) {
    this.store = store;
    this.config = config;
    this.log = log;
    this.sessions = new Map();
    // Envois terminés récemment : un « complete » rejoué (réponse perdue) renvoie le même accusé.
    this.completed = new Map();
    this.inFlight = 0;
  }

  pendingBytes(boxId) {
    let total = 0;
    for (const session of this.sessions.values()) {
      if (boxId === undefined || session.boxId === boxId) total += session.size;
    }
    return total;
  }

  async start(box, input) {
    const name = cleanFileName(input && input.name);
    if (!name) throw new UploadError(400, 'Le nom du fichier est manquant.');
    if (!allowedExtension(name)) {
      const ext = extOf(name);
      throw new UploadError(415, ext ? `Ce format n'est pas accepté : .${ext}.` : 'Ce fichier n\'a pas d\'extension reconnue.');
    }
    const size = input.size;
    if (!Number.isSafeInteger(size) || size <= 0) throw new UploadError(400, 'Le fichier est vide.');
    if (size > this.config.maxFileBytes) {
      throw new UploadError(413, `Le fichier dépasse ${formatGo(this.config.maxFileBytes)}. Découpez-le ou compressez-le.`);
    }

    // Vérifications et réservation sans aucune attente entre elles : des requêtes parallèles ne
    // peuvent pas dépasser ensemble les limites.
    if (this.sessions.size >= MAX_SESSIONS) {
      throw new UploadError(503, 'Trop d\'envois en cours sur le serveur. Réessayez dans quelques minutes.');
    }
    let open = 0;
    for (const session of this.sessions.values()) if (session.boxId === box.id) open += 1;
    if (open >= MAX_SESSIONS_PER_BOX) {
      throw new UploadError(429, 'Trop d\'envois en cours pour cet espace. Attendez la fin des envois en cours.');
    }
    if (this.store.usage(box.id) + this.pendingBytes(box.id) + size > this.config.boxQuotaBytes) {
      throw new UploadError(507, 'Cet espace de dépôt est plein. Prévenez Aymen Benali.');
    }
    const id = randomHex(16);
    const session = {
      id,
      fileId: randomHex(16),
      boxId: box.id,
      name,
      size,
      uploaderName: cleanText(input.uploaderName, 120),
      message: cleanText(input.message, 2000),
      chunkSize: CHUNK_SIZE,
      chunks: chunkCount(size, CHUNK_SIZE),
      next: 0,
      busy: true,
      key: crypto.randomBytes(32),
      prefix: crypto.randomBytes(8),
      hash: crypto.createHash('sha256'),
      handle: null,
      tmpPath: path.join(this.store.tmpDir, `${id}.part`),
      touched: Date.now(),
    };
    this.sessions.set(id, session);

    try {
      const free = await this.store.freeBytes();
      if (free - this.pendingBytes() < this.config.minFreeBytes) {
        throw new UploadError(507, 'Le serveur manque de place pour ce fichier. Prévenez Aymen Benali.');
      }
      session.handle = await fsp.open(session.tmpPath, 'wx', 0o600);
      session.busy = false;
      return { uploadId: id, chunkSize: session.chunkSize, chunks: session.chunks };
    } catch (error) {
      await this.discard(session);
      throw error;
    }
  }

  session(box, uploadId) {
    const session = this.sessions.get(uploadId);
    if (!session || session.boxId !== box.id) {
      throw new UploadError(404, 'Cet envoi a expiré. Relancez l\'envoi du fichier.');
    }
    return session;
  }

  // readBody(expected) lit exactement le bloc annoncé ; s'il échoue, rien ne change côté serveur.
  async receiveChunk(box, uploadId, index, readBody) {
    const session = this.session(box, uploadId);
    if (session.busy || index !== session.next) {
      throw new UploadError(409, 'Bloc inattendu.', { next: session.next });
    }
    // Chaque bloc en cours occupe quelques Mo de mémoire : leur nombre est plafonné.
    if (this.inFlight >= MAX_CHUNKS_IN_FLIGHT) {
      throw new UploadError(503, 'Serveur occupé. Nouvel essai dans un instant.');
    }
    session.busy = true;
    this.inFlight += 1;
    try {
      const data = await readBody(chunkLength(session.size, index, session.chunkSize));
      // Le disque a pu se remplir depuis le début de l'envoi (autres services du serveur).
      if ((await this.store.freeBytes()) < this.config.minFreeBytes / 2) {
        throw new UploadError(507, 'Le serveur manque de place. Prévenez Aymen Benali.');
      }
      const sealed = encryptChunk(session.key, session.prefix, index, index === session.chunks - 1, data);
      const { bytesWritten } = await session.handle.write(sealed, 0, sealed.length, index * (session.chunkSize + TAG_LENGTH));
      if (bytesWritten !== sealed.length) throw new UploadError(507, 'Écriture incomplète sur le serveur. Prévenez Aymen Benali.');
      session.hash.update(data);
      session.next += 1;
      session.touched = Date.now();
      return { next: session.next };
    } finally {
      this.inFlight -= 1;
      session.busy = false;
    }
  }

  async finish(box, uploadId) {
    const session = this.sessions.get(uploadId);
    if (!session) {
      const done = this.completed.get(uploadId);
      if (done && done.boxId === box.id) return done.meta;
    }
    this.session(box, uploadId);
    if (session.busy || session.next !== session.chunks) {
      throw new UploadError(409, 'Le fichier n\'est pas arrivé en entier.', { next: session.next });
    }
    session.busy = true;
    const meta = {
      id: session.fileId,
      boxId: session.boxId,
      name: session.name,
      size: session.size,
      sha256: session.hash.digest('hex'),
      uploaderName: session.uploaderName,
      message: session.message,
      uploadedAt: new Date().toISOString(),
      key: session.key.toString('base64'),
      prefix: session.prefix.toString('base64'),
      chunkSize: session.chunkSize,
    };
    try {
      await session.handle.sync();
      const { size } = await session.handle.stat();
      if (size !== session.size + session.chunks * TAG_LENGTH) throw new Error('fichier temporaire incomplet');
      await session.handle.close();
      session.handle = null;
      await this.store.commitFile(meta, session.tmpPath);
      this.sessions.delete(uploadId);
      this.completed.set(uploadId, { boxId: box.id, meta, at: Date.now() });
      return meta;
    } catch (error) {
      await this.discard(session);
      throw error;
    }
  }

  async abort(box, uploadId) {
    const session = this.sessions.get(uploadId);
    if (session && session.boxId === box.id && !session.busy) await this.discard(session);
  }

  async discard(session) {
    this.sessions.delete(session.id);
    if (session.handle) {
      try {
        await session.handle.close();
      } catch {
        // déjà fermé
      }
      session.handle = null;
    }
    await fsp.rm(session.tmpPath, { force: true });
  }

  async sweep() {
    const now = Date.now();
    for (const session of [...this.sessions.values()]) {
      if (!session.busy && now - session.touched > IDLE_MS) await this.discard(session);
    }
    for (const [id, done] of this.completed) {
      if (now - done.at > RECEIPT_MS) this.completed.delete(id);
    }
  }
}

module.exports = { Uploads, UploadError, MAX_SESSIONS, MAX_SESSIONS_PER_BOX, MAX_CHUNKS_IN_FLIGHT };
