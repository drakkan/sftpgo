// Runs before the first paint, so that dark mode users never see a light flash.
(function () {
  'use strict';
  const root = document.documentElement;
  const media = window.matchMedia('(prefers-color-scheme: dark)');

  function stored() {
    try {
      return localStorage.getItem('webclient-theme') || 'auto';
    } catch {
      return 'auto';
    }
  }

  function apply() {
    const choice = stored();
    root.dataset.themeChoice = choice;
    root.dataset.theme = choice === 'auto' ? (media.matches ? 'dark' : 'light') : choice;
  }

  apply();
  media.addEventListener('change', apply);
  window.addEventListener('storage', apply);
  window.applyTheme = apply;
})();
