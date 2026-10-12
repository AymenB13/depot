// Espace d'administration : copier un lien, confirmer les actions irréversibles.
(() => {
  'use strict';

  for (const button of document.querySelectorAll('[data-copy]')) {
    button.addEventListener('click', async () => {
      const input = document.getElementById(button.dataset.copy);
      try {
        await navigator.clipboard.writeText(input.value);
      } catch {
        input.select();
        document.execCommand('copy');
      }
      const label = button.textContent;
      button.textContent = 'Lien copié';
      setTimeout(() => {
        button.textContent = label;
      }, 2000);
    });
  }

  for (const input of document.querySelectorAll('input.link')) {
    input.addEventListener('focus', () => input.select());
  }

  for (const form of document.querySelectorAll('form[data-confirm]')) {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  }
})();
