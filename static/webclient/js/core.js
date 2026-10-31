// Helpers shared by every WebClient page: translations, the language picker, requests,
// dialogs, menus and notifications. Classic script rather than ES module, so that each
// file can carry the nonce of a strict Content-Security-Policy.
(function () {
  'use strict';

  const root = document.documentElement;
  const staticURL = root.dataset.static || '/static';
  const languages = (root.dataset.languages || '').split(' ').filter(Boolean);
  const offered = languages.length ? languages : ['en'];
  const languageNames = {
    en: 'English',
    pl: 'Polski',
    de: 'Deutsch',
    fr: 'Français',
    es: 'Español',
    it: 'Italiano',
    'zh-CN': '简体中文',
  };

  const $ = (selector, parent = document) => parent.querySelector(selector);
  const $$ = (selector, parent = document) => [...parent.querySelectorAll(selector)];
  const t = (key, options) => i18next.t(key, options);

  function icon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    svg.setAttribute('class', 'icon');
    svg.setAttribute('aria-hidden', 'true');
    use.setAttribute('href', `${staticURL}/webclient/icons.svg#${name}`);
    svg.append(use);
    return svg;
  }

  // Builds an element: h('a.row', { href }, 'text', child). Strings are always text nodes,
  // so file names coming from the server can never become markup.
  function h(spec, attributes, ...children) {
    const [tag, ...classes] = spec.split('.');
    const element = document.createElement(tag || 'div');
    if (classes.length) element.className = classes.join(' ');
    for (const [name, value] of Object.entries(attributes || {})) {
      if (value === undefined || value === null || value === false) continue;
      if (name === 'dataset') Object.assign(element.dataset, value);
      else if (name.startsWith('on')) element.addEventListener(name.slice(2), value);
      else if (name in element && name !== 'list') element[name] = value;
      else element.setAttribute(name, value === true ? '' : value);
    }
    element.append(...children.flat().filter((child) => child !== null && child !== undefined && child !== false));
    return element;
  }

  function translate(parent = document) {
    const nodes = $$('[data-i18n]', parent);
    if (parent.dataset && parent.dataset.i18n) nodes.push(parent);
    for (const node of nodes) {
      let options;
      if (node.dataset.i18nOptions) {
        try {
          options = JSON.parse(node.dataset.i18nOptions);
        } catch {
          options = undefined;
        }
      }
      for (const entry of node.dataset.i18n.split(';')) {
        const match = entry.match(/^\[([^\]]+)\](.+)$/);
        if (match) node.setAttribute(match[1], t(match[2], options));
        else node.textContent = t(entry, options);
      }
    }
    const title = root.dataset.title;
    const brand = root.dataset.brand;
    document.title = title ? `${brand} - ${t(title)}` : brand;
    root.lang = i18next.resolvedLanguage || 'en';
  }

  function setupLanguagePickers() {
    for (const picker of $$('[data-language-picker]')) {
      const label = picker.closest('.language');
      picker.replaceChildren(...offered.map((code) => new Option(languageNames[code] || code, code)));
      picker.value = i18next.resolvedLanguage;
      if (label) label.hidden = offered.length < 2;
      picker.addEventListener('change', async () => {
        await i18next.changeLanguage(picker.value);
        for (const other of $$('[data-language-picker]')) other.value = picker.value;
        translate();
        document.dispatchEvent(new CustomEvent('languagechange'));
      });
    }
  }

  function setupSprites() {
    for (const use of $$('use[data-sprite]')) {
      use.setAttribute('href', `${staticURL}/webclient/icons.svg#${use.dataset.sprite}`);
    }
  }

  function setupTheme() {
    const order = ['auto', 'light', 'dark'];
    const names = { auto: 'theme.system', light: 'theme.light', dark: 'theme.dark' };
    for (const button of $$('[data-theme-toggle]')) {
      button.addEventListener('click', () => {
        const next = order[(order.indexOf(root.dataset.themeChoice) + 1) % order.length];
        try {
          localStorage.setItem('webclient-theme', next);
        } catch {
          // Only this page changes when the browser refuses to store it.
          root.dataset.themeChoice = next;
        }
        window.applyTheme();
        toast('info', t(names[next]));
        document.dispatchEvent(new CustomEvent('themechange'));
      });
    }
  }

  function setupAccountMenu() {
    const button = $('[data-account-menu]');
    if (!button) return;
    button.addEventListener('click', () => {
      const data = button.dataset;
      const items = [{ icon: 'user-round', label: t('title.profile'), href: data.profile }];
      if (data.password) items.push({ icon: 'key-round', label: t('title.change_password'), href: data.password });
      if (data.mfa) items.push({ icon: 'shield-check', label: t('title.two_factor_auth'), href: data.mfa });
      if (data.apikeys) items.push({ icon: 'key-round', label: t('title.api_keys'), href: data.apikeys });
      items.push({ separator: true }, { icon: 'log-out', label: t('login.signout'), href: data.logout });
      openMenu(button, items);
    });
  }

  function setupPasswordFields() {
    for (const input of $$('input[type=password]')) {
      const toggle = h('button.reveal', { type: 'button', ariaLabel: t('client.show_password') }, icon('eye'));
      toggle.addEventListener('click', () => {
        const hidden = input.type === 'password';
        input.type = hidden ? 'text' : 'password';
        toggle.replaceChildren(icon(hidden ? 'eye-off' : 'eye'));
      });
      input.parentElement.classList.add('has-reveal');
      input.after(toggle);
    }
  }

  // Forms post normally. This only prevents a second submit while the first one runs.
  function setupForms() {
    for (const form of $$('form[data-busy]')) {
      form.addEventListener('submit', () => {
        // A redirect to a download leaves this page open, and the button must still work.
        if ('checkRedirect' in form.dataset && new URLSearchParams(location.search).get('next')) return;
        const submit = $('[type=submit]', form);
        if (submit) window.setTimeout(() => { submit.disabled = true; }, 0);
      });
    }
  }

  function dirName(path) {
    const index = path.lastIndexOf('/');
    return index <= 0 ? '/' : path.slice(0, index);
  }

  function joinPath(parent, name) {
    return parent === '/' ? `/${name}` : `${parent}/${name}`;
  }

  function formatSize(bytes) {
    if (bytes === '' || bytes === null || bytes === undefined) return '';
    if (bytes < 1024) return `${bytes} B`;
    const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'];
    const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length);
    const value = bytes / 1024 ** exponent;
    return `${value.toLocaleString(i18next.resolvedLanguage, { maximumFractionDigits: 1 })} ${units[exponent - 1]}`;
  }

  function formatDate(milliseconds) {
    if (!milliseconds) return '';
    return new Date(milliseconds).toLocaleString(i18next.resolvedLanguage, { dateStyle: 'medium', timeStyle: 'short' });
  }

  function csrfToken() {
    const meta = $('meta[name=csrf-token]');
    return meta ? meta.content : '';
  }

  class RequestError extends Error {
    constructor(status, message) {
      super(message);
      this.status = status;
    }
  }

  // The server's messages are translation keys when it has a specific one to give.
  function errorText(error, fallback) {
    const message = error && error.message;
    if (message && i18next.exists(message)) return t(message);
    return fallback ? t(fallback) : t('general.error500');
  }

  async function request(url, options = {}) {
    const headers = { 'X-CSRF-TOKEN': csrfToken(), ...options.headers };
    let body = options.body;
    if (options.json !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(options.json);
    }
    const response = await fetch(url, {
      method: options.method || 'GET',
      credentials: 'same-origin',
      headers,
      body,
      signal: options.signal,
    });
    // An expired session redirects, and fetch follows that to the login page.
    if (response.redirected && new URL(response.url).pathname.endsWith('/login')) {
      window.location.assign(`${response.url.split('?')[0]}?next=${encodeURIComponent(location.pathname + location.search)}`);
      throw new RequestError(401, 'general.expired_session');
    }
    const text = await response.text();
    let data = text;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      // Not JSON: keep the text.
    }
    if (!response.ok) {
      const message = data && typeof data === 'object' ? data.message || data.error : '';
      throw new RequestError(response.status, message);
    }
    return { data, headers: response.headers, status: response.status };
  }

  // Keeps long-lived pages working: a form token only lasts a few hours.
  function refreshTokenEvery(milliseconds) {
    window.setInterval(async () => {
      try {
        const page = await (await fetch(location.href, { credentials: 'same-origin' })).text();
        const fresh = new DOMParser().parseFromString(page, 'text/html').querySelector('meta[name=csrf-token]');
        if (fresh) {
          $('meta[name=csrf-token]').content = fresh.content;
          for (const field of $$('input[name=_form_token]')) field.value = fresh.content;
        }
      } catch {
        // The next attempt or the next page load gets a new token.
      }
    }, milliseconds);
  }

  function toast(kind, message) {
    const names = { success: 'circle-check', error: 'triangle-alert', info: 'info' };
    const item = h(`div.toast.toast-${kind}`, null, icon(names[kind] || 'info'), h('span', null, message));
    $('#toasts').append(item);
    window.setTimeout(() => item.remove(), kind === 'error' ? 8000 : 3500);
  }

  // A native dialog gives focus trapping, Escape and the backdrop for free.
  function dialog({ title, body, actions, onOpen, wide }) {
    return new Promise((resolve) => {
      const element = h(`dialog.dialog${wide ? '.dialog-wide' : ''}`);
      const close = (value) => {
        element.close();
        element.remove();
        resolve(value);
      };
      const footer = h('footer.dialog-actions', null, actions.map((action) => h(
        `button.button${action.kind ? `.button-${action.kind}` : ''}`,
        {
          type: action.submit ? 'submit' : 'button',
          dataset: action.submit ? { submit: '' } : {},
          onclick: action.submit ? undefined : () => close(action.value),
        },
        action.label,
      )));
      const form = h('form', {
        method: 'dialog',
        onsubmit: (event) => {
          event.preventDefault();
          const submit = actions.find((action) => action.submit);
          if (submit) {
            const value = submit.value();
            if (value !== undefined) close(value);
          }
        },
      }, h('h2.dialog-title', null, title), h('div.dialog-body', null, body), footer);
      element.append(form);
      element.addEventListener('cancel', (event) => {
        event.preventDefault();
        close(undefined);
      });
      document.body.append(element);
      element.showModal();
      if (onOpen) onOpen(element, close);
    });
  }

  function confirmDialog({ title, message, confirm, danger }) {
    return dialog({
      title,
      body: h('p', null, message),
      actions: [
        { label: t('client.cancel'), value: false },
        { label: confirm, value: true, kind: danger ? 'danger' : 'primary' },
      ],
    });
  }

  function promptDialog({ title, label, value = '', confirm, validate }) {
    const input = h('input.input', { type: 'text', value, required: true, autocomplete: 'off', spellcheck: false });
    const problem = h('p.field-error', { hidden: true });
    return dialog({
      title,
      body: h('label.field', null, h('span.field-label', null, label), input, problem),
      actions: [
        { label: t('client.cancel'), value: undefined },
        {
          label: confirm,
          kind: 'primary',
          submit: true,
          value: () => {
            const text = input.value.trim();
            const message = validate ? validate(text) : '';
            problem.hidden = !message;
            problem.textContent = message || '';
            return message ? undefined : text;
          },
        },
      ],
      onOpen: () => {
        input.focus();
        const dot = value.lastIndexOf('.');
        input.setSelectionRange(0, dot > 0 ? dot : value.length);
      },
    });
  }

  let closeOpenMenu = null;

  function openMenu(anchor, items) {
    if (closeOpenMenu) {
      const reopening = anchor.getAttribute('aria-expanded') === 'true';
      closeOpenMenu();
      if (reopening) return;
    }
    const menu = h('div.menu', { role: 'menu' });
    const close = () => {
      menu.remove();
      anchor.setAttribute('aria-expanded', 'false');
      document.removeEventListener('pointerdown', outside, true);
      document.removeEventListener('keydown', keys, true);
      window.removeEventListener('resize', close);
      closeOpenMenu = null;
    };
    const outside = (event) => {
      if (!menu.contains(event.target) && !anchor.contains(event.target)) close();
    };
    const keys = (event) => {
      const entries = $$('[role=menuitem]', menu);
      const index = entries.indexOf(document.activeElement);
      if (event.key === 'Escape' || event.key === 'Tab') {
        event.preventDefault();
        close();
        anchor.focus();
      } else if (event.key === 'ArrowDown') {
        event.preventDefault();
        entries[(index + 1) % entries.length].focus();
      } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        entries[(index - 1 + entries.length) % entries.length].focus();
      }
    };
    for (const item of items) {
      if (item.separator) {
        menu.append(h('hr.menu-line', { role: 'separator' }));
        continue;
      }
      const tag = item.href ? 'a' : 'button';
      menu.append(h(`${tag}.menu-item${item.danger ? '.menu-danger' : ''}`, {
        role: 'menuitem',
        href: item.href,
        type: item.href ? undefined : 'button',
        target: item.target,
        download: item.download,
        tabIndex: -1,
        onclick: () => {
          close();
          if (item.action) item.action();
        },
      }, icon(item.icon), h('span', null, item.label)));
    }
    document.body.append(menu);
    const box = anchor.getBoundingClientRect();
    const width = menu.offsetWidth;
    const height = menu.offsetHeight;
    const left = Math.max(8, Math.min(box.right - width, window.innerWidth - width - 8));
    const below = box.bottom + 6;
    const top = below + height > window.innerHeight - 8 ? Math.max(8, box.top - height - 6) : below;
    menu.style.left = `${left}px`;
    menu.style.top = `${top}px`;
    anchor.setAttribute('aria-expanded', 'true');
    closeOpenMenu = close;
    document.addEventListener('pointerdown', outside, true);
    document.addEventListener('keydown', keys, true);
    window.addEventListener('resize', close);
    const first = $('[role=menuitem]', menu);
    if (first) first.focus();
  }

  const ready = i18next
    .use(i18nextHttpBackend)
    .use(i18nextBrowserLanguageDetector)
    .init({
      // English stays loadable so that strings missing from a language do not show as keys.
      supportedLngs: [...new Set([...offered, 'en'])],
      fallbackLng: 'en',
      load: 'currentOnly',
      returnEmptyString: false,
      interpolation: { escapeValue: false },
      detection: {
        order: ['querystring', 'localStorage', 'navigator'],
        lookupQuerystring: 'lng',
        caches: ['localStorage'],
      },
      backend: {
        loadPath: `${staticURL}/locales/{{lng}}/{{ns}}.json?v=${encodeURIComponent(root.dataset.version || '')}`,
      },
    })
    .then(async () => {
      if (!offered.includes(i18next.resolvedLanguage)) await i18next.changeLanguage(offered[0]);
    })
    .catch((error) => console.error(error))
    .then(() => {
      setupSprites();
      translate();
      setupLanguagePickers();
      setupTheme();
      setupAccountMenu();
      setupPasswordFields();
      setupForms();
      root.classList.add('ready');
    });

  window.WC = {
    $,
    $$,
    h,
    t,
    icon,
    ready,
    translate,
    request,
    toast,
    dialog,
    confirmDialog,
    promptDialog,
    openMenu,
    errorText,
    formatSize,
    formatDate,
    dirName,
    joinPath,
    csrfToken,
    refreshTokenEvery,
    staticURL,
  };
})();
