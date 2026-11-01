// The list pages. Each page names itself with data-list, and only the columns and actions
// differ from one to another.
(function () {
  'use strict';
  const { $, h, t, request, toast, confirmDialog, errorText, formatDate, formatSize } = WC;
  const { page, can, table, badge, statusBadge, linkButton, plainButton, removeRow } = WA;

  const encode = encodeURIComponent;
  const actionTypes = {
    1: 'http', 2: 'command', 3: 'email', 4: 'backup', 5: 'user_quota_reset', 6: 'folder_quota_reset',
    7: 'transfer_quota_reset', 8: 'data_retention_check', 9: 'filesystem', 11: 'password_expiration_check',
    12: 'user_expiration_check', 13: 'idp_check', 14: 'user_inactivity_check', 15: 'rotate_logs',
  };
  const triggers = {
    1: 'fs_event', 2: 'provider_event', 3: 'schedule', 4: 'ip_blocked', 5: 'certificate_renewal', 6: 'on_demand', 7: 'idp_login',
  };
  const scopes = { 1: 'apikey.scope_admin', 2: 'apikey.scope_user', 3: 'apikey.scope_user_web_session' };
  const ipProtocols = [[1, 'SSH'], [2, 'FTP'], [4, 'DAV'], [8, 'HTTP']];

  const nameLink = (url, name) => h('a', { href: `${url}/${encode(name)}` }, name);
  const dateText = (value) => (value ? formatDate(value) : t('apikey.never'));
  const count = (list) => (list ? list.length : 0);
  const names = (list) => (list || []).map((entry) => (typeof entry === 'string' ? entry : entry.name)).join(', ');

  async function fetchRows(url) {
    const { data } = await request(url);
    return data || [];
  }

  function quotaText(row) {
    const size = row.quota_size ? `${formatSize(row.used_quota_size || 0)} / ${formatSize(row.quota_size)}` : formatSize(row.used_quota_size || 0);
    const files = row.quota_files ? `${row.used_quota_files || 0} / ${row.quota_files}` : String(row.used_quota_files || 0);
    return `${size} · ${files}`;
  }

  async function runQuotaScan(url) {
    try {
      await request(url, { method: 'POST' });
      toast('success', t('general.quota_scan_started'));
    } catch (error) {
      toast('error', errorText(error, error.status === 409 ? 'general.quota_scan_conflit' : 'general.quota_scan_error'));
    }
  }

  const hasSecondFactor = (row) => Boolean(row.filters && ((row.filters.totp_config && row.filters.totp_config.enabled) || row.filters.passkeys));

  async function disableMFA(url, list) {
    const confirmed = await confirmDialog({
      title: t('2fa.disable_msg'),
      message: t('2fa.disable_question'),
      confirm: t('general.disable_confirm_btn'),
      danger: true,
    });
    if (!confirmed) return;
    try {
      await request(url, { method: 'PUT' });
      list.reload();
    } catch (error) {
      toast('error', errorText(error, '2fa.save_err'));
    }
  }

  function usersList(root) {
    async function bulkRun(path, body, question, button) {
      const confirmed = await confirmDialog({
        title: t('general.actions'),
        message: t(question, { count: body.usernames.length }),
        confirm: t('general.confirm'),
        danger: button,
      });
      if (!confirmed) return;
      try {
        const { data } = await request(`${page.users}/bulk/${path}`, { method: 'POST', json: body });
        const failed = data.failed || [];
        if (failed.length) toast('error', t('user.bulk_partial', { succeeded: data.succeeded.length, failed: failed.length }));
        else toast('success', t('user.bulk_done', { count: data.succeeded.length }));
      } catch (error) {
        toast('error', errorText(error, 'user.bulk_error'));
      }
      list.reload();
    }
    const bulkActions = [];
    if (can('edit_users')) {
      bulkActions.push(
        { label: () => t('general.enable'), icon: 'check', run: (usernames) => bulkRun('status', { usernames, status: 1 }, 'user.bulk_enable_confirm', false) },
        { label: () => t('general.disable'), icon: 'ban', run: (usernames) => bulkRun('status', { usernames, status: 0 }, 'user.bulk_disable_confirm', true) },
      );
    }
    if (can('del_users')) {
      bulkActions.push({ label: () => t('general.delete'), icon: 'trash-2', danger: true, run: (usernames) => bulkRun('delete', { usernames }, 'user.bulk_delete_confirm', true) });
    }
    const list = table({
      root,
      load: () => fetchRows(`${page.users}/json`),
      rowId: (row) => row.username,
      bulk: bulkActions.length ? { actions: bulkActions, selectAll: (total) => t('user.select_all', { count: total }) } : undefined,
      tools: () => (can('add_users') ? [linkButton(t('title.add_user'), page.user)] : []),
      columns: [
        { key: 'username', title: () => t('login.username'), render: (row) => (can('edit_users') ? nameLink(page.user, row.username) : row.username) },
        { key: 'status', title: () => t('general.status'), value: (row) => (row.status === 1 ? t('general.active') : t('general.inactive')), render: (row) => statusBadge(row.status === 1) },
        { key: 'role', title: () => t('general.role') },
        { key: 'groups', title: () => t('title.groups'), value: (row) => names(row.groups), wrap: true },
        { key: 'quota', title: () => t('virtual_folders.quota_size'), value: quotaText, sort: (row) => row.used_quota_size || 0 },
        { key: 'last_login', title: () => t('general.last_login'), value: (row) => dateText(row.last_login), sort: (row) => row.last_login || 0 },
        { key: 'expiration_date', title: () => t('general.expiration'), value: (row) => (row.expiration_date ? formatDate(row.expiration_date) : ''), sort: (row) => row.expiration_date || 0 },
      ],
      actions: (row) => {
        const items = [];
        if (can('edit_users')) items.push({ icon: 'pencil', label: t('general.edit'), href: `${page.user}/${encode(row.username)}` });
        if (can('add_users')) items.push({ icon: 'copy', label: t('general.template'), href: `${page.userTemplate}?from=${encode(row.username)}` });
        if (can('quota_scans')) items.push({ icon: 'gauge', label: t('general.quota_scan'), action: () => runQuotaScan(`${page.quotaUser}/${encode(row.username)}`) });
        if (can('disable_mfa') && hasSecondFactor(row)) {
          items.push({ icon: 'shield-check', label: t('2fa.disable_msg'), action: () => disableMFA(`${page.user}/${encode(row.username)}/2fa/disable`, list) });
        }
        if (can('del_users')) items.push({ icon: 'trash-2', label: t('general.delete'), danger: true, action: () => removeRow({ url: `${page.user}/${encode(row.username)}`, name: row.username, list }) });
        return items;
      },
    });
  }

  function adminsList(root) {
    const list = table({
      root,
      load: () => fetchRows(`${page.admins}/json`),
      tools: () => [linkButton(t('title.add_admin'), page.admin)],
      columns: [
        { key: 'username', title: () => t('login.username'), render: (row) => nameLink(page.admin, row.username) },
        { key: 'status', title: () => t('general.status'), value: (row) => (row.status === 1 ? t('general.active') : t('general.inactive')), render: (row) => statusBadge(row.status === 1) },
        { key: 'email', title: () => t('general.email') },
        { key: 'role', title: () => t('general.role') },
        { key: 'last_login', title: () => t('general.last_login'), value: (row) => dateText(row.last_login), sort: (row) => row.last_login || 0 },
        { key: 'description', title: () => t('general.description'), wrap: true },
      ],
      actions: (row) => {
        const items = [{ icon: 'pencil', label: t('general.edit'), href: `${page.admin}/${encode(row.username)}` }];
        if (hasSecondFactor(row)) {
          items.push({ icon: 'shield-check', label: t('2fa.disable_msg'), action: () => disableMFA(`${page.admin}/${encode(row.username)}/2fa/disable`, list) });
        }
        if (row.username !== page.self) {
          items.push({ icon: 'trash-2', label: t('general.delete'), danger: true, action: () => removeRow({ url: `${page.admin}/${encode(row.username)}`, name: row.username, list }) });
        }
        return items;
      },
    });
  }

  function apiKeysList(root) {
    const list = table({
      root,
      load: () => fetchRows(`${page.apikeys}/json`),
      tools: () => [linkButton(t('title.add_api_key'), page.apikey)],
      columns: [
        { key: 'name', title: () => t('general.name'), render: (row) => h('a', { href: `${page.apikey}/${encode(row.id)}` }, row.name) },
        { key: 'scope', title: () => t('apikey.scope'), value: (row) => t(scopes[row.scope] || 'general.unsupported') },
        { key: 'owner', title: () => t('apikey.bound_to'), value: (row) => row.user || row.admin || t('apikey.any') },
        { key: 'expires_at', title: () => t('apikey.expires'), value: (row) => dateText(row.expires_at), sort: (row) => row.expires_at || 0 },
        { key: 'last_use_at', title: () => t('apikey.last_use'), value: (row) => dateText(row.last_use_at), sort: (row) => row.last_use_at || 0 },
        { key: 'description', title: () => t('general.description'), wrap: true },
      ],
      actions: (row) => [
        { icon: 'pencil', label: t('general.edit'), href: `${page.apikey}/${encode(row.id)}` },
        { icon: 'trash-2', label: t('general.delete'), danger: true, action: () => removeRow({ url: `${page.apikey}/${encode(row.id)}`, name: row.name, list }) },
      ],
    });
  }

  function membersText(row) {
    return t('general.members_summary', { users: count(row.users), admins: count(row.admins) });
  }

  function groupsList(root) {
    const list = table({
      root,
      load: () => fetchRows(`${page.groups}/json`),
      tools: () => [linkButton(t('title.add_group'), page.group)],
      columns: [
        { key: 'name', title: () => t('general.name'), render: (row) => nameLink(page.group, row.name) },
        { key: 'description', title: () => t('general.description'), wrap: true },
        { key: 'members', title: () => t('general.members'), value: membersText, sort: (row) => count(row.users) + count(row.admins), search: false },
      ],
      actions: (row) => [
        { icon: 'pencil', label: t('general.edit'), href: `${page.group}/${encode(row.name)}` },
        { icon: 'trash-2', label: t('general.delete'), danger: true, action: () => removeRow({ url: `${page.group}/${encode(row.name)}`, name: row.name, list }) },
      ],
    });
  }

  function foldersList(root) {
    const list = table({
      root,
      load: () => fetchRows(`${page.folders}/json`),
      tools: () => [linkButton(t('title.add_folder'), page.folder)],
      columns: [
        { key: 'name', title: () => t('general.name'), render: (row) => nameLink(page.folder, row.name) },
        { key: 'mapped_path', title: () => t('storage.home_dir'), wrap: true },
        { key: 'quota', title: () => t('virtual_folders.quota_size'), value: quotaText, sort: (row) => row.used_quota_size || 0 },
        { key: 'associations', title: () => t('general.associations'), value: (row) => t('virtual_folders.associations_summary', { users: count(row.users), groups: count(row.groups) }), search: false },
        { key: 'description', title: () => t('general.description'), wrap: true },
      ],
      actions: (row) => {
        const items = [
          { icon: 'pencil', label: t('general.edit'), href: `${page.folder}/${encode(row.name)}` },
          { icon: 'copy', label: t('general.template'), href: `${page.folderTemplate}?from=${encode(row.name)}` },
        ];
        if (can('quota_scans')) items.push({ icon: 'gauge', label: t('general.quota_scan'), action: () => runQuotaScan(`${page.quotaFolder}/${encode(row.name)}`) });
        items.push({ icon: 'trash-2', label: t('general.delete'), danger: true, action: () => removeRow({ url: `${page.folder}/${encode(row.name)}`, name: row.name, list }) });
        return items;
      },
    });
  }

  function rolesList(root) {
    const list = table({
      root,
      load: () => fetchRows(`${page.roles}/json`),
      tools: () => [linkButton(t('title.add_role'), page.role)],
      columns: [
        { key: 'name', title: () => t('general.name'), render: (row) => nameLink(page.role, row.name) },
        { key: 'description', title: () => t('general.description'), wrap: true },
        { key: 'members', title: () => t('general.members'), value: membersText, sort: (row) => count(row.users) + count(row.admins), search: false },
      ],
      actions: (row) => [
        { icon: 'pencil', label: t('general.edit'), href: `${page.role}/${encode(row.name)}` },
        { icon: 'trash-2', label: t('general.delete'), danger: true, action: () => removeRow({ url: `${page.role}/${encode(row.name)}`, name: row.name, list }) },
      ],
    });
  }

  function actionsList(root) {
    const list = table({
      root,
      load: () => fetchRows(`${page.actions}/json`),
      tools: () => [linkButton(t('title.add_action'), page.action)],
      columns: [
        { key: 'name', title: () => t('general.name'), render: (row) => nameLink(page.action, row.name) },
        { key: 'type', title: () => t('general.type'), value: (row) => t(`actions.types.${actionTypes[row.type]}`) },
        { key: 'rules', title: () => t('title.event_rules'), value: (row) => names(row.rules), wrap: true },
        { key: 'description', title: () => t('general.description'), wrap: true },
      ],
      actions: (row) => [
        { icon: 'pencil', label: t('general.edit'), href: `${page.action}/${encode(row.name)}` },
        { icon: 'trash-2', label: t('general.delete'), danger: true, action: () => removeRow({ url: `${page.action}/${encode(row.name)}`, name: row.name, list }) },
      ],
    });
  }

  function rulesList(root) {
    async function run(row) {
      const confirmed = await confirmDialog({ title: t('rules.run'), message: t('rules.run_confirm'), confirm: t('rules.run_confirm_btn') });
      if (!confirmed) return;
      try {
        await request(`${page.rule}/run/${encode(row.name)}`, { method: 'POST' });
        toast('success', t('rules.run_ok'));
      } catch (error) {
        toast('error', errorText(error, 'rules.run_error_generic'));
      }
    }
    const list = table({
      root,
      load: () => fetchRows(`${page.rules}/json`),
      tools: () => [linkButton(t('title.add_rule'), page.rule)],
      columns: [
        { key: 'name', title: () => t('general.name'), render: (row) => nameLink(page.rule, row.name) },
        { key: 'status', title: () => t('general.status'), value: (row) => (row.status === 1 ? t('general.active') : t('general.inactive')), render: (row) => statusBadge(row.status === 1) },
        { key: 'trigger', title: () => t('rules.trigger'), value: (row) => t(`rules.triggers.${triggers[row.trigger]}`) },
        { key: 'actions', title: () => t('title.event_actions'), value: (row) => names(row.actions), wrap: true },
        { key: 'description', title: () => t('general.description'), wrap: true },
      ],
      actions: (row) => {
        const items = [{ icon: 'pencil', label: t('general.edit'), href: `${page.rule}/${encode(row.name)}` }];
        if (row.trigger === 6) items.push({ icon: 'play', label: t('rules.run'), action: () => run(row) });
        items.push({ icon: 'trash-2', label: t('general.delete'), danger: true, action: () => removeRow({ url: `${page.rule}/${encode(row.name)}`, name: row.name, list }) });
        return items;
      },
    });
  }

  function transfersText(row) {
    const transfers = (row.active_transfers || []).map((item) => t(item.operation_type === 'upload' ? 'connections.upload' : 'connections.download', { path: item.path }));
    return [...transfers, row.command].filter(Boolean).join(' · ');
  }

  function connectionsList(root) {
    async function disconnect(row) {
      const confirmed = await confirmDialog({
        title: t('general.actions'),
        message: t('connections.disconnect_confirm'),
        confirm: t('connections.disconnect_confirm_btn'),
        danger: true,
      });
      if (!confirmed) return;
      const node = row.node ? `?node=${encode(row.node)}` : '';
      try {
        await request(`${page.connections}/${encode(row.connection_id)}${node}`, { method: 'DELETE' });
        window.setTimeout(list.reload, 1000);
      } catch (error) {
        toast('error', errorText(error, 'connections.disconnect_ko'));
      }
    }
    const list = table({
      root,
      load: () => fetchRows(`${page.connections}/json`),
      tools: (self) => [plainButton(t('general.refresh'), 'refresh-cw', () => self.reload())],
      columns: [
        { key: 'username', title: () => t('login.username') },
        { key: 'protocol', title: () => t('general.protocol') },
        { key: 'remote_address', title: () => t('connections.remote_address') },
        { key: 'connection_time', title: () => t('connections.started'), value: (row) => formatDate(row.connection_time), sort: (row) => row.connection_time || 0 },
        { key: 'last_activity', title: () => t('connections.last_activity'), value: (row) => formatDate(row.last_activity), sort: (row) => row.last_activity || 0 },
        { key: 'info', title: () => t('general.info'), value: transfersText, wrap: true },
        { key: 'node', title: () => t('connections.node') },
      ],
      actions: can('close_conns') ? (row) => [{ icon: 'unplug', label: t('connections.disconnect_confirm_btn'), danger: true, action: () => disconnect(row) }] : undefined,
    });
  }

  function defenderList(root) {
    const list = table({
      root,
      load: () => fetchRows(root.dataset.hosts),
      tools: (self) => [plainButton(t('general.refresh'), 'refresh-cw', () => self.reload())],
      columns: [
        { key: 'ip', title: () => t('defender.ip') },
        { key: 'ban_time', title: () => t('defender.ban_time'), value: (row) => (row.ban_time ? formatDate(Date.parse(row.ban_time)) : ''), sort: (row) => Date.parse(row.ban_time) || 0 },
        { key: 'score', title: () => t('defender.score'), value: (row) => row.score || 0 },
      ],
      actions: can('manage_defender') ? (row) => [
        { icon: 'trash-2', label: t('general.delete'), danger: true, action: () => removeRow({ url: `${root.dataset.hosts}/${encode(row.id)}`, name: row.ip, list }) },
      ] : undefined,
    });
  }

  function ipProtocolsText(row) {
    if (!row.protocols) return t('ip_list.any');
    return ipProtocols.filter(([bit]) => row.protocols & bit).map(([, name]) => name).join(', ');
  }

  // The lists can be large and the server pages by the last address seen.
  async function fetchIPEntries(type, filter) {
    const limit = 500;
    const rows = [];
    let from = '';
    for (;;) {
      const query = new URLSearchParams({ limit: String(limit), order: 'ASC' });
      if (filter) query.set('filter', filter);
      if (from) query.set('from', from);
      const { data } = await request(`${page.iplists}/${type}?${query}`);
      rows.push(...(data || []));
      if (!data || data.length < limit || rows.length >= 10000) return rows;
      from = data[data.length - 1].ipornet;
    }
  }

  function ipLists(root) {
    const picker = $('#list-type');
    const filter = $('#list-filter');
    const notice = $('#list-disabled');
    const type = () => picker.value;
    const list = table({
      root,
      load: () => fetchIPEntries(type(), filter.value.trim()),
      tools: () => [linkButton(t('general.add'), `${page.iplist}/${type()}`)],
      columns: [
        { key: 'ipornet', title: () => t('ip_list.ip_net'), render: (row) => h('a', { href: `${page.iplist}/${type()}/${encode(row.ipornet)}` }, row.ipornet) },
        { key: 'mode', title: () => t('general.mode'), value: (row) => (row.mode === 1 ? t('ip_list.allow') : t('ip_list.deny')), render: (row) => badge(row.mode === 1 ? t('ip_list.allow') : t('ip_list.deny'), row.mode === 1 ? 'ok' : 'off') },
        { key: 'protocols', title: () => t('ip_list.protocols'), value: ipProtocolsText, search: false },
        { key: 'updated_at', title: () => t('general.last_modified'), value: (row) => formatDate(row.updated_at), sort: (row) => row.updated_at || 0, search: false },
        { key: 'description', title: () => t('general.description'), wrap: true },
      ],
      actions: (row) => [
        { icon: 'pencil', label: t('general.edit'), href: `${page.iplist}/${type()}/${encode(row.ipornet)}` },
        { icon: 'trash-2', label: t('general.delete'), danger: true, action: () => removeRow({ url: `${page.iplist}/${type()}/${encode(row.ipornet)}`, name: row.ipornet, list }) },
      ],
    });
    function refreshNotice() {
      const option = picker.selectedOptions[0];
      notice.hidden = option.dataset.enabled === 'true';
      $('p', notice).textContent = t(option.dataset.off);
    }
    picker.addEventListener('change', () => {
      refreshNotice();
      list.refreshTools();
      list.reload();
    });
    $('#list-search').addEventListener('click', () => list.reload());
    filter.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        list.reload();
      }
    });
    refreshNotice();
  }

  const lists = {
    users: usersList,
    admins: adminsList,
    apikeys: apiKeysList,
    groups: groupsList,
    folders: foldersList,
    roles: rolesList,
    actions: actionsList,
    rules: rulesList,
    connections: connectionsList,
    defender: defenderList,
    iplists: ipLists,
  };

  WC.ready.then(() => {
    const root = $('[data-list]');
    if (root) lists[root.dataset.list](root);
  });
})();
