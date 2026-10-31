// The list of shares and the dialog with their public links.
(function () {
  'use strict';
  const { $, h, t, icon, request, toast, dialog, confirmDialog, openMenu, errorText } = WC;

  const page = $('#shares');
  const data = page.dataset;
  const SCOPE_READ = 1;
  const SCOPE_WRITE = 2;
  let shares = [];
  let filter = '';

  function scopeLabel(scope) {
    if (scope === SCOPE_READ) return t('share.scope_read');
    if (scope === SCOPE_WRITE) return t('share.scope_write');
    return t('share.scope_read_write');
  }

  function linksFor(share) {
    const base = `${data.base || location.origin}${data.public}/${encodeURIComponent(share.id)}`;
    if (share.scope === SCOPE_WRITE) {
      return [{ title: t('share.upload_desc'), url: `${base}/upload` }];
    }
    const links = [
      { title: t('share.link_single_title'), help: t('share.link_single_desc'), url: base },
      { title: t('share.link_dir_title'), help: t('share.link_dir_desc'), url: `${base}/browse` },
      { title: t('share.link_uncompressed_title'), help: t('share.link_uncompressed_desc'), url: `${base}?compress=false` },
    ];
    if (share.scope !== SCOPE_READ) links.push({ title: t('share.upload_desc'), url: `${base}/upload` });
    return links;
  }

  function linkRow(link) {
    const field = h('input.input', { type: 'text', value: link.url, readOnly: true, ariaLabel: link.title });
    return h('div.field', null,
      h('span.field-label', null, link.title),
      link.help ? h('span.field-help', null, link.help) : null,
      h('div.link-row', null, field, h('button.button.button-square', {
        type: 'button',
        ariaLabel: t('general.copy_link'),
        title: t('general.copy_link'),
        onclick: async () => {
          try {
            await navigator.clipboard.writeText(link.url);
            toast('success', t('general.copied'));
          } catch {
            field.select();
          }
        },
      }, icon('copy'))));
  }

  function showLinks(share) {
    return dialog({
      title: t('share.access_links_title'),
      wide: true,
      body: linksFor(share).map(linkRow),
      actions: [{ label: t('general.close'), value: true, kind: 'primary' }],
    });
  }

  async function remove(share) {
    const confirmed = await confirmDialog({
      title: t('general.delete'),
      message: t('general.delete_confirm', { name: share.name }),
      confirm: t('general.delete_confirm_btn'),
      danger: true,
    });
    if (!confirmed) return;
    try {
      await request(`${data.share}/${encodeURIComponent(share.id)}`, { method: 'DELETE' });
      await load();
    } catch (error) {
      toast('error', errorText(error, 'general.delete_error_generic'));
    }
  }

  function usage(share) {
    const parts = [];
    if (share.password) parts.push(t('share.password_protected'));
    if (share.expires_at) parts.push(t('share.expiration_date', { val: new Date(share.expires_at) }).trim());
    if (share.last_use_at) parts.push(t('share.last_use', { val: new Date(share.last_use_at) }).trim());
    if (share.max_tokens) parts.push(t('share.usage', { used: share.used_tokens || 0, total: share.max_tokens }).trim());
    else parts.push(t('share.used_tokens', { used: share.used_tokens || 0 }).trim());
    return parts.join(' ');
  }

  function menu(share) {
    return [
      { icon: 'link', label: t('general.copy_link'), action: () => showLinks(share) },
      { icon: 'pencil', label: t('general.edit'), href: `${data.share}/${encodeURIComponent(share.id)}` },
      { separator: true },
      { icon: 'trash-2', label: t('general.delete'), danger: true, action: () => remove(share) },
    ];
  }

  function render() {
    const list = $('#list');
    const shown = shares.filter((share) => !filter || share.name.toLowerCase().includes(filter));
    if (!shown.length) {
      list.replaceChildren(filter
        ? h('div.empty', null, icon('search'), h('p', null, t('client.no_matches', { term: filter })))
        : h('div.empty', null, icon('share-2'), h('p', null, t('share.no_share'))));
      return;
    }
    list.replaceChildren(h('table.listing.listing-stack', null,
      h('thead', null, h('tr', null,
        h('th', { scope: 'col' }, t('general.name')),
        h('th', { scope: 'col' }, t('share.scope')),
        h('th', { scope: 'col' }, t('general.info')),
        h('th.col-actions', { scope: 'col' }, h('span.sr', null, t('general.actions'))))),
      h('tbody', null, shown.map((share) => h('tr', null,
        h('td', { dataset: { label: t('general.name') } },
          h('a.entry-name', { href: `${data.share}/${encodeURIComponent(share.id)}` }, share.name),
          share.description ? h('span.entry-where', null, share.description) : null,
          h('span.entry-where', null, (share.paths || []).join(', '))),
        h('td', { dataset: { label: t('share.scope') } }, scopeLabel(share.scope)),
        h('td', { dataset: { label: t('general.info') } }, usage(share)),
        h('td.col-actions', null, h('button.iconbutton', {
          type: 'button',
          ariaLabel: t('client.more_actions', { name: share.name }),
          ariaHasPopup: 'menu',
          onclick: (event) => openMenu(event.currentTarget, menu(share)),
        }, icon('ellipsis'))))))));
  }

  async function load() {
    try {
      const { data: rows } = await request(data.list);
      shares = rows || [];
      render();
    } catch (error) {
      $('#list').replaceChildren(h('div.empty', null, icon('triangle-alert'), h('p', null, errorText(error))));
    }
  }

  WC.ready.then(() => {
    $('#search').addEventListener('input', (event) => {
      filter = event.target.value.trim().toLowerCase();
      render();
    });
    document.addEventListener('languagechange', render);
    load();
  });
})();
