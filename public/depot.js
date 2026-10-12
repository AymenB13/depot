// Page de dépôt : les fichiers partent dès qu'ils sont choisis, en blocs de 1 Mo.
// Aucune donnée saisie n'est insérée en HTML : tout passe par textContent.
(() => {
  'use strict';

  const root = document.querySelector('[data-depot]');
  if (!root) return;

  const api = `/api/d/${root.dataset.token}/uploads`;
  const maxBytes = Number(root.dataset.max);
  const allowed = new Set(root.dataset.ext.split(','));

  const $ = (id) => document.getElementById(id);
  const drop = $('drop');
  const picker = $('picker');
  const queue = $('queue');
  const alertBox = $('alert');
  const done = $('done');

  const items = [];
  let sending = false;
  const number = new Intl.NumberFormat('fr-FR', { maximumFractionDigits: 1 });

  function size(bytes) {
    if (bytes < 1024) return `${bytes} o`;
    const units = ['Ko', 'Mo', 'Go', 'To'];
    let value = bytes / 1024;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    return `${number.format(value < 10 ? value : Math.round(value))} ${units[unit]}`;
  }

  function extOf(name) {
    const match = /\.([A-Za-z0-9]{1,8})$/.exec(name);
    return match ? match[1].toLowerCase() : '';
  }

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  function failure(message, status) {
    const error = new Error(message);
    error.status = status;
    return error;
  }

  // ---- Liste des fichiers ----

  function addFiles(list) {
    alertBox.hidden = true;
    done.hidden = true;
    for (const file of list) {
      const item = { file, state: 'ready', error: '', progress: 0, upload: null };
      const ext = extOf(file.name);
      if (!allowed.has(ext)) item.error = ext ? `Format non accepté (.${ext}).` : 'Ce fichier n\'a pas d\'extension reconnue.';
      else if (file.size === 0) item.error = 'Ce fichier est vide.';
      else if (file.size > maxBytes) item.error = `Ce fichier dépasse ${size(maxBytes)}.`;
      if (item.error) item.state = 'refused';
      items.push(item);
      render(item);
    }
    sendAll();
  }

  function button(label, action) {
    const element = node('button', 'link-button', label);
    element.type = 'button';
    element.addEventListener('click', action);
    return element;
  }

  function render(item) {
    if (!item.row) {
      item.row = node('li');
      item.row.append(node('span', 'name', item.file.name), node('span', 'size', size(item.file.size)));
      item.line = node('div', 'line');
      item.row.append(item.line);
      queue.append(item.row);
    }
    item.line.className = 'line';
    item.line.replaceChildren();
    if (item.state !== 'sending' && item.bar) {
      item.bar.remove();
      item.bar = null;
    }
    switch (item.state) {
      case 'ready':
        item.line.textContent = 'En attente';
        break;
      case 'sending': {
        if (!item.bar) {
          item.bar = node('progress');
          item.bar.max = 100;
          item.row.insertBefore(item.bar, item.line);
        }
        const percent = Math.floor(item.progress * 100);
        item.bar.value = percent;
        item.line.textContent = `Envoi en cours… ${percent} %`;
        break;
      }
      case 'done':
        item.line.classList.add('ok');
        item.line.textContent = '✓ Reçu';
        break;
      case 'failed':
        item.line.classList.add('error');
        item.line.append(
          node('span', '', item.error),
          button('Réessayer', () => {
            item.state = 'ready';
            render(item);
            sendAll();
          }),
        );
        break;
      default:
        item.line.classList.add('error');
        item.line.append(
          node('span', '', item.error),
          button('Retirer', () => {
            items.splice(items.indexOf(item), 1);
            item.row.remove();
          }),
        );
    }
  }

  // ---- Envoi ----

  async function request(method, url, body) {
    for (let attempt = 1; ; attempt += 1) {
      let response;
      try {
        response = await fetch(url, {
          method,
          body,
          headers: body ? { 'Content-Type': 'application/json' } : {},
          credentials: 'omit',
          cache: 'no-store',
        });
      } catch {
        if (attempt < 4) {
          await wait(1000 * 2 ** attempt);
          continue;
        }
        throw new Error('La connexion a été interrompue.');
      }
      const data = await response.json().catch(() => ({}));
      if (response.ok) return data;
      if ((response.status >= 500 || response.status === 429) && attempt < 4) {
        await wait(1000 * 2 ** attempt);
        continue;
      }
      throw failure(data.error || `Erreur ${response.status}.`, response.status);
    }
  }

  function put(url, blob, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('PUT', url);
      xhr.responseType = 'json';
      // Un peu moins que le délai du proxy (60 s par requête).
      xhr.timeout = 55000;
      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable) onProgress(event.loaded);
      };
      xhr.onload = () => resolve({ status: xhr.status, data: xhr.response || {} });
      xhr.onerror = () => reject(new Error('reseau'));
      xhr.ontimeout = () => reject(new Error('reseau'));
      xhr.send(blob);
    });
  }

  async function sendChunk(url, blob, onProgress) {
    for (let attempt = 1; ; attempt += 1) {
      let result;
      try {
        result = await put(url, blob, onProgress);
      } catch {
        if (attempt < 6) {
          await wait(1000 * 2 ** Math.min(attempt, 4));
          continue;
        }
        throw new Error('La connexion a été interrompue.');
      }
      const { status, data } = result;
      if (status === 200) return data;
      // Bloc déjà reçu (réponse perdue en route) : on reprend où en est le serveur.
      if (status === 409 && Number.isInteger(data.next)) return data;
      if ((status >= 500 || status === 429) && attempt < 6) {
        await wait(1000 * 2 ** Math.min(attempt, 4));
        continue;
      }
      throw failure(data.error || `Erreur ${status}.`, status);
    }
  }

  // Un envoi interrompu reprend là où le serveur s'est arrêté ; s'il a expiré, il repart de zéro.
  async function sendOne(item) {
    item.state = 'sending';
    render(item);
    if (!item.upload) {
      const start = await request('POST', api, JSON.stringify({ name: item.file.name, size: item.file.size }));
      item.upload = { id: start.uploadId, chunkSize: start.chunkSize, chunks: start.chunks, next: 0 };
    }
    const upload = item.upload;
    const total = item.file.size;
    try {
      while (upload.next < upload.chunks) {
        const from = upload.next * upload.chunkSize;
        const blob = item.file.slice(from, Math.min(from + upload.chunkSize, total));
        const result = await sendChunk(`${api}/${upload.id}/${upload.next}`, blob, (loaded) => {
          item.progress = Math.min(1, (from + loaded) / total);
          render(item);
        });
        upload.next = result.next;
        item.progress = Math.min(1, (upload.next * upload.chunkSize) / total);
        render(item);
      }
      await request('POST', `${api}/${upload.id}/complete`);
      item.upload = null;
      item.state = 'done';
      render(item);
    } catch (error) {
      if (error.status === 404) item.upload = null;
      throw error;
    }
  }

  async function sendAll() {
    if (sending) return;
    sending = true;
    let item;
    while ((item = items.find((candidate) => candidate.state === 'ready'))) {
      try {
        await sendOne(item);
      } catch (error) {
        item.state = 'failed';
        item.error = error.message || 'L\'envoi a échoué.';
        render(item);
      }
    }
    sending = false;
    if (items.some((candidate) => candidate.state === 'failed')) {
      alertBox.textContent = 'Un envoi n\'a pas abouti. Vérifiez votre connexion, puis cliquez sur Réessayer.';
      alertBox.hidden = false;
    }
    done.hidden = !(items.some((candidate) => candidate.state === 'done') && items.every((candidate) => candidate.state === 'done'));
  }

  // ---- Événements ----

  $('choose').addEventListener('click', (event) => {
    event.stopPropagation();
    picker.click();
  });
  drop.addEventListener('click', () => picker.click());
  picker.addEventListener('change', () => {
    addFiles(picker.files);
    picker.value = '';
  });

  // Un fichier lâché à côté de la zone ne doit pas s'ouvrir dans le navigateur.
  window.addEventListener('dragover', (event) => event.preventDefault());
  window.addEventListener('drop', (event) => event.preventDefault());
  let depth = 0;
  drop.addEventListener('dragenter', () => {
    depth += 1;
    drop.classList.add('over');
  });
  drop.addEventListener('dragleave', () => {
    depth = Math.max(0, depth - 1);
    if (depth === 0) drop.classList.remove('over');
  });
  drop.addEventListener('drop', (event) => {
    event.preventDefault();
    depth = 0;
    drop.classList.remove('over');
    if (event.dataTransfer && event.dataTransfer.files.length) addFiles(event.dataTransfer.files);
  });

  window.addEventListener('beforeunload', (event) => {
    if (!sending) return;
    event.preventDefault();
    event.returnValue = '';
  });
})();
