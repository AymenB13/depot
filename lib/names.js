'use strict';

// Noms de fichiers et textes saisis par les déposants : nettoyés, jamais utilisés comme chemin.

const ALLOWED_EXTENSIONS = [
  'pdf', 'xlsx', 'xlsm', 'xlsb', 'xls', 'csv', 'tsv', 'txt', 'json', 'xml', 'parquet',
  'docx', 'doc', 'pptx', 'ppt', 'odt', 'ods', 'odp', 'rtf',
  'zip', '7z', 'rar', 'gz', 'tgz',
  'png', 'jpg', 'jpeg', 'webp', 'heic',
];
const ALLOWED = new Set(ALLOWED_EXTENSIONS);

// Caractères de contrôle et d'inversion de sens d'écriture (ex. « facture‮fdp.exe »).
const HIDDEN = /[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;
const HIDDEN_KEEP_LINES = /[\u0000-\u0009\u000b-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;

function extOf(name) {
  const match = /\.([A-Za-z0-9]{1,8})$/.exec(name);
  return match ? match[1].toLowerCase() : '';
}

function allowedExtension(name) {
  return ALLOWED.has(extOf(name));
}

function cleanFileName(raw) {
  if (typeof raw !== 'string') return '';
  let name = raw.toWellFormed().normalize('NFC').split(/[\\/]/).pop() || '';
  name = name.replace(HIDDEN, '').replace(/\s+/g, ' ').trim().replace(/^\.+/, '');
  // Coupe par caractère entier (jamais au milieu d'un emoji).
  const chars = Array.from(name);
  if (chars.length > 180) {
    const ext = extOf(name);
    name = ext ? `${chars.slice(0, 179 - ext.length).join('')}.${ext}` : chars.slice(0, 180).join('');
  }
  return name;
}

function cleanText(raw, max) {
  if (typeof raw !== 'string') return '';
  const text = raw.toWellFormed().normalize('NFC').replace(/\r\n?/g, '\n').replace(HIDDEN_KEEP_LINES, '').trim();
  return Array.from(text).slice(0, max).join('');
}

// Nom de secours en ASCII pour l'en-tête Content-Disposition.
function asciiFallback(name) {
  const ascii = name.normalize('NFKD').replace(/[^\x20-\x7e]/g, '').replace(/["\\;]/g, '_').trim();
  return ascii || 'document';
}

function contentDisposition(rawName) {
  const name = String(rawName).toWellFormed();
  const encoded = encodeURIComponent(name).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  return `attachment; filename="${asciiFallback(name)}"; filename*=UTF-8''${encoded}`;
}

module.exports = {
  ALLOWED_EXTENSIONS,
  extOf,
  allowedExtension,
  cleanFileName,
  cleanText,
  asciiFallback,
  contentDisposition,
};
