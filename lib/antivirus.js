'use strict';

// Analyse antivirus par ClamAV (clamd, protocole INSTREAM) : le fichier est déchiffré en mémoire,
// bloc par bloc, et envoyé au conteneur depot-clamav, joignable seulement depuis le portail.

const net = require('node:net');
const { once } = require('node:events');
const { decryptedChunks } = require('./files');

function collect(socket) {
  const answer = new Promise((resolve, reject) => {
    let text = '';
    socket.on('data', (data) => {
      text += data.toString('utf8');
    });
    socket.on('end', () => resolve(text));
    socket.on('close', () => resolve(text));
    socket.on('error', reject);
    socket.on('timeout', () => {
      reject(new Error('antivirus muet'));
      socket.destroy();
    });
  });
  answer.catch(() => {});
  return answer;
}

function drainOrClose(socket) {
  return new Promise((resolve) => {
    if (socket.destroyed) {
      resolve();
      return;
    }
    const done = () => {
      socket.off('drain', done);
      socket.off('close', done);
      resolve();
    };
    socket.on('drain', done);
    socket.on('close', done);
  });
}

async function scanFile(store, meta, { host, port, timeoutMs = 10 * 60 * 1000 }) {
  if (!host) return { status: 'error', detail: 'antivirus non configuré' };
  const socket = net.createConnection({ host, port });
  socket.setTimeout(120_000);
  const answer = collect(socket);
  const timer = setTimeout(() => socket.destroy(new Error('délai dépassé')), timeoutMs);
  try {
    await once(socket, 'connect');
    socket.write('zINSTREAM\0');
    for await (const plain of decryptedChunks(store, meta)) {
      if (socket.destroyed) throw new Error('connexion à l\'antivirus fermée');
      const header = Buffer.alloc(4);
      header.writeUInt32BE(plain.length, 0);
      socket.write(header);
      if (!socket.write(plain)) await drainOrClose(socket);
    }
    if (socket.destroyed) throw new Error('connexion à l\'antivirus fermée');
    socket.write(Buffer.alloc(4));
    const text = (await answer).replace(/\0/g, '').trim();
    const found = /^stream: (.+) FOUND$/.exec(text);
    if (text === 'stream: OK') return { status: 'clean' };
    if (found) return { status: 'infected', signature: found[1].slice(0, 200) };
    return { status: 'error', detail: text.slice(0, 200) || 'réponse vide' };
  } catch (error) {
    return { status: 'error', detail: error.message };
  } finally {
    clearTimeout(timer);
    socket.destroy();
  }
}

module.exports = { scanFile };
