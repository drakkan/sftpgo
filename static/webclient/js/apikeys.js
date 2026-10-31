// The user's own API keys. A key is shown once, when it is created.
(function () {
  'use strict';
  const { $, h, t, icon, request, toast, dialog, confirmDialog, errorText, formatDate } = WC;

  const page = $('#apikeys');
  const url = page.dataset.url;
  const allowed = page.dataset.allowed === 'true';
  const WEB_SESSION_SCOPE = 3;
  let keys = [];

  function scopeLabel(key) {
    return t(key.scope === WEB_SESSION_SCOPE ? 'apikey.scope_user_web_session' : 'apikey.scope_user');
  }

  function expiryLabel(key) {
    if (!key.expires_at) return t('apikey.never');
    const text = formatDate(key.expires_at);
    return key.expires_at < Date.now() ? `${text} (${t('general.expired')})` : text;
  }

  function render() {
    const holder = $('#keys');
    if (!keys.length) {
      holder.replaceChildren(h('div.empty', null, icon('key-round'), h('p', null, t('client.keys_empty'))));
      return;
    }
    holder.replaceChildren(h('table.listing.listing-stack', null,
      h('thead', null, h('tr', null, [
        t('general.name'), t('apikey.scope'), t('apikey.last_use'), t('apikey.expires'),
      ].map((label) => h('th', { scope: 'col' }, label)), h('th.col-actions', { scope: 'col' }, h('span.sr', null, t('general.actions'))))),
      h('tbody', null, keys.map((key) => h('tr', null,
        h('td', { dataset: { label: t('general.name') } },
          h('span.entry-name', null, key.name),
          key.description ? h('span.entry-where', null, key.description) : null),
        h('td', { dataset: { label: t('apikey.scope') } }, scopeLabel(key)),
        h('td', { dataset: { label: t('apikey.last_use') } }, key.last_use_at ? formatDate(key.last_use_at) : t('apikey.never')),
        h('td', { dataset: { label: t('apikey.expires') } }, expiryLabel(key)),
        h('td.col-actions', null, h('button.iconbutton', {
          type: 'button',
          ariaLabel: t('client.key_revoke', { name: key.name }),
          title: t('client.key_revoke', { name: key.name }),
          onclick: () => revoke(key),
        }, icon('trash-2'))))))));
  }

  async function load() {
    try {
      const { data } = await request(`${url}/json`);
      keys = data || [];
      render();
    } catch (error) {
      $('#keys').replaceChildren(h('div.empty', null, icon('triangle-alert'), h('p', null, errorText(error))));
    }
  }

  async function revoke(key) {
    const confirmed = await confirmDialog({
      title: t('client.key_revoke', { name: key.name }),
      message: t('client.key_revoke_confirm'),
      confirm: t('client.key_revoke_button'),
      danger: true,
    });
    if (!confirmed) return;
    try {
      await request(`${url}/${encodeURIComponent(key.id)}`, { method: 'DELETE' });
      toast('success', t('client.key_revoked'));
      await load();
    } catch (error) {
      toast('error', errorText(error));
    }
  }

  // The time is entered as local time, the server wants milliseconds since the epoch.
  function readExpiry(input) {
    return input.value ? new Date(input.value).getTime() : 0;
  }

  async function showKey(value) {
    const field = h('input.input', { type: 'text', value, readOnly: true, spellcheck: false });
    const copy = h('button.button', {
      type: 'button',
      onclick: async () => {
        try {
          await navigator.clipboard.writeText(value);
          toast('success', t('general.copied'));
        } catch {
          field.select();
        }
      },
    }, icon('copy'), h('span', null, t('general.copy')));
    await dialog({
      title: t('client.key_created'),
      body: [
        h('div.notice.notice-warn', null, icon('info'), h('p', null, t('apikey.generated_help'))),
        h('div.link-row', null, field, copy),
      ],
      actions: [{ label: t('client.key_saved'), value: true, kind: 'primary' }],
      onOpen: () => field.select(),
    });
  }

  async function add() {
    const name = h('input.input', { type: 'text', required: true, maxLength: 255, autocomplete: 'off' });
    const description = h('input.input', { type: 'text', autocomplete: 'off' });
    const expires = h('input.input', { type: 'datetime-local' });
    const session = h('input', { type: 'checkbox' });
    const problem = h('p.field-error', { hidden: true });
    const values = await dialog({
      title: t('title.add_api_key'),
      body: [
        h('label.field', null, h('span.field-label', null, t('general.name')), name),
        h('label.field', null, h('span.field-label', null, t('general.description')), description),
        h('label.field', null, h('span.field-label', null, t('apikey.expires')), expires,
          h('span.field-help', null, t('client.key_expiry_help'))),
        h('label.switch', null, session, h('span', null,
          h('strong', null, t('client.key_web_session')), h('br'),
          h('span.field-help', null, t('client.key_web_session_help')))),
        problem,
      ],
      actions: [
        { label: t('client.cancel'), value: undefined },
        {
          label: t('title.add_api_key'),
          kind: 'primary',
          submit: true,
          value: () => {
            const expiresAt = readExpiry(expires);
            const message = expiresAt && expiresAt <= Date.now() ? t('share.expiration_past') : '';
            problem.hidden = !message;
            problem.textContent = message;
            if (message) return undefined;
            return {
              name: name.value.trim(),
              description: description.value.trim(),
              expires_at: expiresAt,
              web_session: session.checked,
            };
          },
        },
      ],
      onOpen: () => name.focus(),
    });
    if (!values) return;
    try {
      const { data } = await request(url, { method: 'POST', json: values });
      await load();
      await showKey(data.key);
    } catch (error) {
      toast('error', errorText(error));
    }
  }

  WC.ready.then(() => {
    if (allowed) $('#add-key').addEventListener('click', add);
    load();
    document.addEventListener('languagechange', render);
  });
})();
