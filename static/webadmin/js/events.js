// The logs page: three searches over the event search plugin, with shared filters.
(function () {
  'use strict';
  const { $, t, request, toast, errorText, formatDate } = WC;
  const { table, badge, plainButton } = WA;

  const batch = 500;
  const eventNames = { 1: 'events.login_failed', 2: 'events.login_missing_user', 3: 'events.no_login_tried', 4: 'events.algo_negotiation_failed', 5: 'events.login_ok' };
  const statusNames = { 1: 'general.ok', 2: 'general.failed', 3: 'events.quota_exceeded' };
  const toNanoseconds = (value) => (value ? `${BigInt(new Date(value).getTime()) * 1000000n}` : '');
  const toDate = (nanoseconds) => formatDate(Math.floor(Number(nanoseconds) / 1e6));

  const views = {
    'pane-fs': {
      url: () => $('#events').dataset.fs,
      filters: () => ({ actions: $('#fs-actions').value, protocols: $('#fs-protocols').value, statuses: $('#fs-status').value }),
      columns: [
        { key: 'action', title: () => t('events.action') },
        { key: 'username', title: () => t('login.username') },
        { key: 'virtual_path', title: () => t('events.path'), value: (row) => [row.virtual_path, row.virtual_target_path].filter(Boolean).join(' > '), wrap: true },
        { key: 'protocol', title: () => t('general.protocol') },
        { key: 'ip', title: () => 'IP' },
        { key: 'status', title: () => t('general.status'), value: (row) => t(statusNames[row.status] || 'general.failed'), render: (row) => badge(t(statusNames[row.status] || 'general.failed'), row.status === 1 ? 'ok' : 'off') },
      ],
    },
    'pane-provider': {
      url: () => $('#events').dataset.provider,
      filters: () => ({ actions: $('#provider-actions').value, object_types: $('#provider-types').value, object_name: $('#provider-name').value }),
      columns: [
        { key: 'action', title: () => t('events.action') },
        { key: 'username', title: () => t('login.username') },
        { key: 'object_type', title: () => t('events.object') },
        { key: 'object_name', title: () => t('general.name'), wrap: true },
        { key: 'ip', title: () => 'IP' },
      ],
    },
    'pane-log': {
      url: () => $('#events').dataset.log,
      filters: () => ({ events: $('#log-event').value, protocols: $('#log-protocols').value }),
      columns: [
        { key: 'event', title: () => t('events.event'), value: (row) => t(eventNames[row.event] || 'general.unsupported') },
        { key: 'username', title: () => t('login.username') },
        { key: 'protocol', title: () => t('general.protocol') },
        { key: 'ip', title: () => 'IP' },
        { key: 'message', title: () => t('general.info'), wrap: true },
      ],
    },
  };

  function queryFor(view) {
    const query = new URLSearchParams({ limit: String(batch), order: 'DESC' });
    const common = {
      start_timestamp: toNanoseconds($('#filter-start').value),
      end_timestamp: toNanoseconds($('#filter-end').value),
      username: $('#filter-username').value.trim(),
      ip: $('#filter-ip').value.trim(),
    };
    for (const [name, value] of Object.entries({ ...common, ...view.filters() })) {
      if (String(value).trim()) query.set(name, String(value).trim());
    }
    return query;
  }

  let current = 'pane-fs';
  const results = {};

  function build(name) {
    const view = views[name];
    results[name] = results[name] || { rows: [], more: false, append: false };
    const result = results[name];
    const list = table({
      root: $('#event-table'),
      sortBy: 'timestamp',
      descending: true,
      load: async () => {
        const query = queryFor(view);
        if (result.append && result.rows.length) query.set('from_id', result.rows[result.rows.length - 1].id);
        const { data } = await request(`${view.url()}?${query}`);
        const page = data || [];
        result.rows = result.append ? [...result.rows, ...page] : page;
        result.append = false;
        result.more = page.length === batch;
        list?.refreshTools();
        return result.rows;
      },
      tools: () => [
        result.more ? plainButton(t('general.next'), 'chevron-right', () => {
          result.append = true;
          list.reload();
        }) : null,
        plainButton(t('general.export'), 'download', () => {
          const query = queryFor(view);
          query.set('csv_export', 'true');
          query.delete('limit');
          window.location.assign(`${view.url()}?${query}`);
        }),
      ].filter(Boolean),
      columns: [
        { key: 'timestamp', title: () => t('events.datetime'), value: (row) => toDate(row.timestamp), sort: (row) => Number(row.timestamp) },
        ...view.columns,
      ],
    });
    return list;
  }

  WC.ready.then(() => {
    const strip = $('[data-tabs]');
    let list = build(current);
    strip.addEventListener('tabchange', (event) => {
      if (event.detail === current) return;
      current = event.detail;
      list = build(current);
    });
    $('#event-filters').addEventListener('submit', (event) => {
      event.preventDefault();
      results[current].append = false;
      list.reload();
    });
  }).catch((error) => toast('error', errorText(error)));
})();
