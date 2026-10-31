// The file browser, for both the signed-in user and a browsable share. Folders open without
// reloading the page, so that uploads keep running while the user moves around.
(function () {
  'use strict';
  const { $, h, t, icon, request, toast, dialog, confirmDialog, promptDialog, openMenu, errorText, formatSize,
    formatDate, dirName, joinPath } = WC;

  const page = $('#files');
  const data = page.dataset;
  const isShare = data.shareMode === '1';
  const CHUNK = 200;

  const images = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg', 'avif']);
  const videos = new Set(['mp4', 'webm', 'mov', 'm4v', 'ogv']);
  const audios = new Set(['mp3', 'ogg', 'oga', 'wav', 'flac', 'm4a', 'aac', 'opus']);
  const thumbnailed = new Set(['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'mp4', 'mov', 'mkv', 'webm', 'avi', 'm4v']);
  const archives = new Set(['zip', 'gz', 'tgz', 'bz2', 'xz', '7z', 'rar', 'tar', 'zst']);
  const code = new Set(['js', 'ts', 'go', 'py', 'sh', 'c', 'h', 'cpp', 'java', 'kt', 'rs', 'rb', 'php', 'html', 'css',
    'json', 'yaml', 'yml', 'xml', 'toml', 'sql']);
  const documents = new Set(['txt', 'md', 'pdf', 'doc', 'docx', 'odt', 'rtf', 'csv', 'xls', 'xlsx', 'ods', 'ppt', 'pptx']);

  function storedOr(key, fallback) {
    try {
      return localStorage.getItem(key) || fallback;
    } catch {
      return fallback;
    }
  }

  function store(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch {
      // Only a preference: it lasts until the page is reloaded.
    }
  }

  const state = {
    cwd: decodeURIComponent((data.current || '%2F').replace(/\+/g, ' ')) || '/',
    entries: [],
    results: null,
    query: '',
    filter: '',
    selected: new Map(),
    sort: storedOr('webclient-sort', 'name:asc'),
    view: storedOr('webclient-view', 'list'),
    shown: 0,
    permissions: new Set(['add', 'mkdir', 'rename', 'delete', 'download', 'copy'].filter((name) => data[`can${name[0].toUpperCase()}${name.slice(1)}`] === 'true')),
    controller: null,
    dragged: null,
  };

  const can = (permission) => state.permissions.has(permission);
  const canShare = () => data.canShare === 'true';
  const visible = () => (state.results || state.entries).filter(matchesFilter);

  function matchesFilter(entry) {
    return !state.filter || entry.name.toLowerCase().includes(state.filter);
  }

  function extension(name) {
    const dot = name.lastIndexOf('.');
    return dot > 0 ? name.slice(dot + 1).toLowerCase() : '';
  }

  function kindOf(entry) {
    if (entry.isDir) return 'folder';
    const ext = extension(entry.name);
    if (images.has(ext)) return 'image';
    if (videos.has(ext)) return 'video';
    if (audios.has(ext)) return 'audio';
    if (ext === 'pdf') return 'pdf';
    return 'file';
  }

  function iconName(entry) {
    if (entry.isDir) return 'folder';
    const ext = extension(entry.name);
    if (images.has(ext)) return 'file-image';
    if (videos.has(ext)) return 'file-video';
    if (audios.has(ext)) return 'file-audio';
    if (archives.has(ext)) return 'file-archive';
    if (code.has(ext)) return 'file-code';
    if (documents.has(ext)) return 'file-text';
    return 'file';
  }

  function folderURL(path) {
    return `${data.files}?path=${encodeURIComponent(path)}`;
  }

  function normalize(row, parent) {
    const isDir = row.type === '1';
    return {
      name: row.name,
      isDir,
      size: isDir || row.size === '' ? '' : row.size,
      modified: row.last_modified,
      url: row.url,
      editURL: row.edit_url,
      parent,
      where: row.path,
      full: joinPath(parent, row.name),
    };
  }

  function compare(a, b) {
    const [key, direction] = state.sort.split(':');
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    let result = 0;
    if (key === 'size') result = (a.size || 0) - (b.size || 0);
    else if (key === 'modified') result = (a.modified || 0) - (b.modified || 0);
    if (!result) result = a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: 'base' });
    return direction === 'desc' ? -result : result;
  }

  async function load(path, { push = false, replace = false } = {}) {
    if (state.controller) state.controller.abort();
    const controller = new AbortController();
    state.controller = controller;
    state.cwd = path;
    state.results = null;
    state.query = '';
    state.filter = '';
    $('#search').value = '';
    state.selected.clear();
    updateSelection();
    renderTabs();
    updateTools();
    $('#list').replaceChildren(h('div.loading', null, t('general.loading')));
    const url = folderURL(path);
    if (push) history.pushState({ path }, '', url);
    else if (replace) history.replaceState({ path }, '', url);
    try {
      const { data: rows, headers } = await request(`${data.dirs}?path=${encodeURIComponent(path)}`, { signal: controller.signal });
      const permissions = headers.get('X-SFTPGO-DIR-PERMISSIONS');
      if (permissions !== null && !isShare) state.permissions = new Set(permissions.split(',').filter(Boolean));
      state.entries = (rows || []).map((row) => normalize(row, path)).sort(compare);
      render();
    } catch (error) {
      if (error.name === 'AbortError') return;
      state.entries = [];
      $('#list').replaceChildren(h('div.empty', null, icon('triangle-alert'), h('p', null, errorText(error, 'fs.dir_list.err_generic'))));
      updateTools();
    }
  }

  function renderTabs() {
    const tabs = $('#tabs');
    const parts = state.cwd.split('/').filter(Boolean);
    const homeLabel = isShare ? t('title.shared_files') : t('fs.home');
    const items = [];
    const makeLink = (path, label, withIcon) => {
      const link = h('a.tab', { href: folderURL(path), onclick: (event) => navigate(event, path) },
        withIcon ? icon('house') : null, h('span.tab-label', null, label));
      bindMoveTarget(link, path);
      return link;
    };
    let path = '/';
    if (parts.length) items.push(makeLink('/', homeLabel, true));
    parts.forEach((part, index) => {
      path = joinPath(path, part);
      if (index < parts.length - 1) items.push(makeLink(path, part, false));
    });
    const title = parts.length ? parts[parts.length - 1] : homeLabel;
    items.push(h('div.tab.tab-current', null, h('h1.tab-title', { title }, title)));
    tabs.replaceChildren(...items);
    tabs.scrollLeft = tabs.scrollWidth;
  }

  function navigate(event, path) {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button) return;
    event.preventDefault();
    load(path, { push: true });
  }

  function updateTools() {
    $('#new-folder').hidden = !can('mkdir') || !!state.results;
    $('#upload').hidden = !can('add') || !!state.results;
    const toggle = $('#view-toggle');
    toggle.replaceChildren(icon(state.view === 'grid' ? 'list' : 'layout-grid'));
    toggle.setAttribute('aria-pressed', String(state.view === 'grid'));
  }

  function selectBox(entry) {
    const input = h('input', {
      type: 'checkbox',
      checked: state.selected.has(entry.full),
      ariaLabel: t('client.select_item', { name: entry.name }),
      onchange: (event) => {
        if (event.target.checked) state.selected.set(entry.full, entry);
        else state.selected.delete(entry.full);
        event.target.closest('[data-path]').classList.toggle('is-selected', event.target.checked);
        updateSelection();
      },
    });
    return h('label.check', null, input);
  }

  function glyph(entry) {
    const box = h('span.glyph', null, icon(iconName(entry)));
    if (!entry.isDir && data.thumbnail && thumbnailed.has(extension(entry.name))) {
      // Stays in the page while loading: a hidden image with lazy loading never starts.
      const image = h('img', { alt: '', loading: 'lazy', src: `${data.thumbnail}?path=${encodeURIComponent(entry.full)}` });
      image.addEventListener('error', () => image.remove());
      box.append(image);
    }
    return box;
  }

  function entryLink(entry) {
    const meta = [entry.isDir ? '' : formatSize(entry.size), formatDate(entry.modified)].filter(Boolean).join(', ');
    return h(`a.entry${entry.isDir ? '.entry-folder' : ''}`, {
      href: entry.isDir ? folderURL(entry.full) : entry.url,
      onclick: (event) => openEntry(event, entry),
    }, glyph(entry), h('span.entry-text', null,
      h('span.entry-name', null, entry.name),
      state.results ? h('button.entry-where', {
        type: 'button',
        onclick: (event) => {
          event.preventDefault();
          event.stopPropagation();
          load(entry.parent, { push: true });
        },
      }, entry.parent) : null,
      h('span.entry-meta', null, meta)));
  }

  function moreButton(entry) {
    return h('button.iconbutton', {
      type: 'button',
      ariaLabel: t('client.more_actions', { name: entry.name }),
      ariaHasPopup: 'menu',
      onclick: (event) => openMenu(event.currentTarget, menuFor(entry)),
    }, icon('ellipsis'));
  }

  function bindRow(row, entry) {
    row.dataset.path = entry.full;
    row.classList.toggle('is-selected', state.selected.has(entry.full));
    if (can('rename') && !state.results) {
      row.draggable = true;
      row.addEventListener('dragstart', (event) => {
        state.dragged = state.selected.has(entry.full) ? [...state.selected.values()] : [entry];
        event.dataTransfer.effectAllowed = 'move';
        event.dataTransfer.setData('text/plain', entry.name);
      });
      row.addEventListener('dragend', () => { state.dragged = null; });
      if (entry.isDir) bindMoveTarget(row, entry.full);
    }
    return row;
  }

  function bindMoveTarget(element, path) {
    const accepts = () => state.dragged && !state.dragged.some((item) => item.full === path || path.startsWith(`${item.full}/`) || item.parent === path);
    element.addEventListener('dragover', (event) => {
      if (!accepts()) return;
      event.preventDefault();
      element.classList.add('is-drop-target');
    });
    element.addEventListener('dragleave', () => element.classList.remove('is-drop-target'));
    element.addEventListener('drop', (event) => {
      element.classList.remove('is-drop-target');
      if (!accepts()) return;
      event.preventDefault();
      event.stopPropagation();
      const items = state.dragged;
      state.dragged = null;
      runBatch('move', items, path);
    });
  }

  function rowFor(entry) {
    return bindRow(h('tr', null,
      h('td.col-check', null, selectBox(entry)),
      h('td', null, entryLink(entry)),
      h('td.col-size', null, formatSize(entry.size)),
      h('td.col-date', null, formatDate(entry.modified)),
      h('td.col-actions', null, moreButton(entry))), entry);
  }

  function cardFor(entry) {
    return bindRow(h('li.card', null, selectBox(entry), moreButton(entry), entryLink(entry)), entry);
  }

  function sortHeader(key, label, className) {
    const [current, direction] = state.sort.split(':');
    const active = current === key;
    const button = h('button.sort', {
      type: 'button',
      onclick: () => {
        state.sort = `${key}:${active && direction === 'asc' ? 'desc' : 'asc'}`;
        store('webclient-sort', state.sort);
        state.entries.sort(compare);
        if (state.results) state.results.sort(compare);
        render();
      },
    }, label, active ? icon(direction === 'asc' ? 'arrow-up' : 'arrow-down') : null);
    return h(`th${className ? `.${className}` : ''}`, {
      scope: 'col',
      ariaSort: active ? (direction === 'asc' ? 'ascending' : 'descending') : undefined,
    }, button);
  }

  function emptyState() {
    if (state.filter || state.results) {
      const term = state.filter || state.query;
      return h('div.empty', null, icon('search'), h('p', null, t('client.no_matches', { term })),
        !state.results && data.search ? h('button.button', { type: 'button', onclick: () => searchEverywhere(term) }, t('client.search_subfolders')) : null);
    }
    if (can('add')) {
      return h('button.empty', { type: 'button', onclick: () => $('#picker').click() },
        icon('upload'), h('strong', null, t('fs.upload.message_empty')));
    }
    return h('div.empty', null, icon('folder'), h('p', null, t('fs.no_files_folders')));
  }

  function render() {
    const entries = visible();
    const list = $('#list');
    state.shown = 0;
    updateTools();
    updateFoot(entries);
    if (!entries.length) {
      list.replaceChildren(emptyState());
      return;
    }
    if (state.view === 'grid') {
      list.replaceChildren(h('ul.gallery', { id: 'rows' }));
    } else {
      const allBox = h('input', {
        type: 'checkbox',
        id: 'select-all',
        ariaLabel: t('client.select_all'),
        onchange: (event) => {
          for (const entry of visible()) {
            if (event.target.checked) state.selected.set(entry.full, entry);
            else state.selected.delete(entry.full);
          }
          render();
          updateSelection();
        },
      });
      allBox.checked = entries.every((entry) => state.selected.has(entry.full));
      list.replaceChildren(h('table.listing', null,
        h('thead', null, h('tr', null,
          h('th.col-check', { scope: 'col' }, h('label.check', null, allBox)),
          sortHeader('name', t('general.name')),
          sortHeader('size', t('general.size'), 'col-size'),
          sortHeader('modified', t('general.last_modified'), 'col-date'),
          h('th.col-actions', { scope: 'col' }, h('span.sr', null, t('general.actions'))))),
        h('tbody', { id: 'rows' })));
    }
    showMore();
  }

  // A folder can hold many thousands of entries: add rows as they come into view.
  const observer = new IntersectionObserver((seen) => {
    if (seen.some((item) => item.isIntersecting)) showMore();
  }, { rootMargin: '600px' });

  function showMore() {
    const entries = visible();
    const rows = $('#rows');
    if (!rows) return;
    const next = entries.slice(state.shown, state.shown + CHUNK);
    rows.append(...next.map(state.view === 'grid' ? cardFor : rowFor));
    state.shown += next.length;
    const sentinel = $('#more');
    observer.disconnect();
    if (state.shown < entries.length) observer.observe(sentinel);
  }

  function updateFoot(entries) {
    const count = $('#count');
    if (state.results) count.textContent = t('client.results', { count: entries.length, folder: state.cwd });
    else count.textContent = t('client.items', { count: entries.length });
  }

  function updateSelection() {
    const bar = $('#selection');
    const items = [...state.selected.values()];
    bar.hidden = !items.length;
    if (!items.length) return;
    $('#selection-count').textContent = t('general.selected_items', { count: items.length });
    $('#selection-download').hidden = !can('download');
    $('#selection-move').hidden = !can('rename') && !can('copy');
    $('#selection-share').hidden = !canShare();
    $('#selection-delete').hidden = !can('delete');
    const allBox = $('#select-all');
    if (allBox) allBox.checked = visible().every((entry) => state.selected.has(entry.full));
  }

  function openEntry(event, entry) {
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.button) return;
    if (entry.isDir) {
      navigate(event, entry.full);
      return;
    }
    const kind = kindOf(entry);
    if (kind === 'image' || kind === 'video' || kind === 'audio') {
      event.preventDefault();
      WC.openViewer(visible().filter((item) => ['image', 'video', 'audio'].includes(kindOf(item))), entry, kindOf);
    } else if (kind === 'pdf') {
      event.preventDefault();
      window.location.assign(`${data.viewpdf}?path=${encodeURIComponent(entry.full)}`);
    } else if (entry.editURL) {
      event.preventDefault();
      window.location.assign(entry.editURL);
    }
  }

  function menuFor(entry) {
    const items = [];
    if (!entry.isDir && can('download')) {
      items.push({ icon: 'download', label: t('fs.download'), href: entry.url, download: entry.name });
    } else if (entry.isDir && can('download')) {
      items.push({ icon: 'download', label: t('fs.download'), action: () => downloadZip([entry]) });
    }
    if (!entry.isDir && entry.editURL) {
      items.push({ icon: 'pencil', label: t('general.edit'), href: entry.editURL });
    }
    if (can('rename') || can('copy')) {
      if (can('rename')) items.push({ icon: 'pencil', label: t('general.rename'), action: () => rename(entry) });
      items.push({ icon: 'folder-input', label: t('fs.move_copy'), action: () => moveOrCopy([entry]) });
    }
    if (canShare()) items.push({ icon: 'share-2', label: t('fs.share'), action: () => share([entry]) });
    if (can('delete')) {
      if (items.length) items.push({ separator: true });
      items.push({ icon: 'trash-2', label: t('general.delete'), danger: true, action: () => remove([entry]) });
    }
    return items;
  }

  function validName(name) {
    if (!name) return t('general.name_required');
    if (name.includes('/')) return t('fs.invalid_name');
    return '';
  }

  async function newFolder() {
    const name = await promptDialog({
      title: t('fs.new_folder'),
      label: t('fs.create_folder_msg'),
      confirm: t('client.create_folder'),
      validate: (value) => (value ? validName(value) : t('fs.folder_name_required')),
    });
    if (!name) return;
    try {
      await request(`${data.dirs}?path=${encodeURIComponent(joinPath(state.cwd, name))}`, { method: 'POST' });
      await load(state.cwd);
    } catch (error) {
      toast('error', errorText(error, messageFor('create_dir', error.status)));
    }
  }

  function messageFor(action, status) {
    if (status === 403) return `fs.${action}.err_403`;
    if (status === 429) return `fs.${action}.err_429`;
    if (status === 409 && (action === 'move' || action === 'copy' || action === 'rename')) return `fs.${action}.err_exists`;
    return `fs.${action}.err_generic`;
  }

  const sleep = (milliseconds) => new Promise((resolve) => { window.setTimeout(resolve, milliseconds); });

  // Moves, copies and folder deletes run on the server and are polled until they finish.
  async function waitForTask(id) {
    for (;;) {
      await sleep(400);
      const { data: task } = await request(`${data.tasks}/${encodeURIComponent(id)}`);
      if (task.status !== 0) return task.status;
    }
  }

  async function renameTask(path, target) {
    const url = `${data.actions}/move?path=${encodeURIComponent(path)}&target=${encodeURIComponent(target)}`;
    const { data: reply } = await request(url, { method: 'POST' });
    return waitForTask(reply.message);
  }

  async function rename(entry) {
    const name = await promptDialog({
      title: t('fs.rename.title', { name: entry.name }),
      label: t('fs.rename.new_name'),
      value: entry.name,
      confirm: t('general.rename'),
      validate: (value) => {
        if (value === entry.name) return t('general.name_different');
        return validName(value);
      },
    });
    if (!name) return;
    try {
      const status = await renameTask(entry.full, joinPath(entry.parent, name));
      if (status !== 200) throw Object.assign(new Error(''), { status });
      await reload();
    } catch (error) {
      toast('error', t(messageFor('rename', error.status), { name: entry.name }));
    }
  }

  async function reload() {
    if (state.results) await searchEverywhere(state.query);
    else await load(state.cwd);
  }

  async function pickFolder(items) {
    let current = state.cwd;
    const listBox = h('div.picker');
    const here = h('p.picker-path');
    const show = async (path) => {
      current = path;
      here.replaceChildren(icon('folder'), h('span', null, path));
      listBox.replaceChildren(h('div.loading', null, t('general.loading')));
      try {
        const { data: rows } = await request(`${data.dirs}?path=${encodeURIComponent(path)}&dirtree=1`);
        const folders = (rows || []).map((row) => row.name).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
        const rowsToShow = [];
        if (path !== '/') {
          rowsToShow.push(h('button.picker-row', { type: 'button', onclick: () => show(dirName(path)) }, icon('arrow-up'), h('span', null, t('general.back'))));
        }
        for (const name of folders) {
          const target = joinPath(path, name);
          if (items.some((item) => item.isDir && item.full === target)) continue;
          rowsToShow.push(h('button.picker-row', { type: 'button', onclick: () => show(target) }, icon('folder'), h('span', null, name)));
        }
        listBox.replaceChildren(...rowsToShow);
        if (!rowsToShow.length) listBox.append(h('p.loading', null, t('fs.no_more_subfolders')));
      } catch (error) {
        listBox.replaceChildren(h('p.loading', null, errorText(error, 'fs.dir_list.err_generic')));
      }
    };
    const actions = [{ label: t('client.cancel'), value: undefined }];
    if (can('copy')) actions.push({ label: t('fs.copy.msg'), value: 'copy' });
    if (can('rename')) actions.push({ label: t('fs.move.msg'), value: 'move', kind: 'primary' });
    const action = await dialog({
      title: t('general.choose_target_folder'),
      body: [here, listBox],
      actions,
      onOpen: () => show(current),
    });
    return action ? { action, target: current } : null;
  }

  async function moveOrCopy(items) {
    const choice = await pickFolder(items);
    if (choice) await runBatch(choice.action, items, choice.target);
  }

  async function runBatch(action, items, target) {
    const status = $('#status');
    let failed = 0;
    let index = 0;
    for (const item of items) {
      index += 1;
      status.textContent = t(action === 'move' ? 'fs.moving' : 'fs.copying', { idx: index, total: items.length });
      try {
        let result;
        if (action === 'move') {
          result = await renameTask(item.full, joinPath(target, item.name));
        } else {
          const url = `${data.actions}/copy?path=${encodeURIComponent(item.full)}&target=${encodeURIComponent(target === '/' ? '/' : `${target}/`)}`;
          const { data: reply } = await request(url, { method: 'POST' });
          result = await waitForTask(reply.message);
        }
        if (result !== 200) throw Object.assign(new Error(''), { status: result });
      } catch (error) {
        failed += 1;
        toast('error', `${item.name}: ${t(messageFor(action, error.status))}`);
      }
    }
    status.textContent = '';
    state.selected.clear();
    updateSelection();
    await reload();
    if (!failed) toast('success', t(action === 'move' ? 'client.moved' : 'client.copied', { count: items.length }));
  }

  async function remove(items) {
    const single = items.length === 1;
    const confirmed = await confirmDialog({
      title: t('general.delete'),
      message: single ? t('general.delete_confirm', { name: items[0].name }) : t('general.delete_multi_confirm'),
      confirm: t('general.delete_confirm_btn'),
      danger: true,
    });
    if (!confirmed) return;
    const status = $('#status');
    let failed = 0;
    let index = 0;
    for (const item of items) {
      index += 1;
      status.textContent = t('fs.deleting', { idx: index, total: items.length });
      try {
        if (item.isDir) {
          const { data: reply } = await request(`${data.dirs}?path=${encodeURIComponent(item.full)}`, { method: 'DELETE' });
          const result = await waitForTask(reply.message);
          if (result !== 200) throw Object.assign(new Error(''), { status: result });
        } else {
          await request(`${data.files}?path=${encodeURIComponent(item.full)}`, { method: 'DELETE' });
        }
      } catch (error) {
        failed += 1;
        toast('error', t(single ? messageFor('delete', error.status) : messageFor('delete_multi', error.status), { name: item.name }));
      }
    }
    status.textContent = '';
    state.selected.clear();
    updateSelection();
    await reload();
    if (!failed) toast('success', t('client.deleted', { count: items.length }));
  }

  // A real form with a blank target: the Android app takes over exactly this kind of post,
  // and a normal browser saves the streamed archive without leaving the page.
  function downloadZip(items) {
    const parents = new Set(items.map((item) => item.parent));
    const base = parents.size === 1 ? [...parents][0] : '/';
    const names = items.map((item) => (parents.size === 1 ? item.name : item.full.slice(1)));
    const form = h('form', { method: 'post', target: '_blank', action: `${data.download}?path=${encodeURIComponent(base)}` },
      h('input', { type: 'hidden', name: '_form_token', value: WC.csrfToken() }),
      h('input', { type: 'hidden', name: 'files', value: JSON.stringify(names) }));
    document.body.append(form);
    form.submit();
    form.remove();
  }

  function share(items) {
    const parents = new Set(items.map((item) => item.parent));
    const base = parents.size === 1 ? [...parents][0] : '/';
    const names = items.map((item) => (parents.size === 1 ? item.name : item.full.slice(1)));
    window.location.assign(`${data.shareUrl}?path=${encodeURIComponent(base)}&files=${encodeURIComponent(JSON.stringify(names))}`);
  }

  async function searchEverywhere(term) {
    const query = term.trim();
    if (!query || !data.search) return;
    if (state.controller) state.controller.abort();
    const controller = new AbortController();
    state.controller = controller;
    state.query = query;
    state.filter = '';
    state.selected.clear();
    updateSelection();
    $('#list').replaceChildren(h('div.loading', null, t('select2.searching')));
    try {
      const url = `${data.search}?path=${encodeURIComponent(state.cwd)}&q=${encodeURIComponent(query)}`;
      const { data: rows } = await request(url, { signal: controller.signal });
      state.results = (rows || []).map((row) => normalize(row, row.path)).sort(compare);
      render();
    } catch (error) {
      if (error.name === 'AbortError') return;
      $('#list').replaceChildren(h('div.empty', null, icon('triangle-alert'), h('p', null, errorText(error, 'fs.err_generic'))));
    }
  }

  function uploadURL(relative) {
    const path = joinPath(state.cwd, relative);
    if (isShare) {
      const base = data.files.replace(/\/browse$/, '');
      return `${base}/${encodeURIComponent(path)}?mkdir_parents=true`;
    }
    return `${data.file}?path=${encodeURIComponent(path)}&mkdir_parents=true`;
  }

  const queue = new WC.TransferQueue({
    pingURL: isShare ? '' : data.ping,
    keepAlive: Number(data.keepalive) || 0,
    onFileDone: (item) => {
      if (item.folder === state.cwd && !queue.isBusy()) load(state.cwd);
    },
  });

  async function upload(found) {
    if (!found.length) {
      toast('error', t('fs.upload_no_files'));
      return;
    }
    const folder = state.cwd;
    const topLevel = [...new Set(found.map((item) => item.relative.split('/')[0]))];
    try {
      const { data: rows } = await request(`${data.exist}?path=${encodeURIComponent(folder)}`, {
        method: 'POST',
        json: { files: topLevel },
      });
      if (!(await WC.confirmOverwrite(topLevel, (rows || []).map((row) => row.name)))) return;
    } catch (error) {
      toast('error', errorText(error, 'fs.upload.err_generic'));
      return;
    }
    const before = queue.items.length;
    queue.add(found.map(({ file, relative }) => ({ file, url: uploadURL(relative), label: relative })));
    for (const item of queue.items.slice(before)) item.folder = folder;
  }

  function bindControls() {
    $('#upload').addEventListener('click', () => $('#picker').click());
    $('#picker').addEventListener('change', (event) => {
      upload([...event.target.files].map((file) => ({ file, relative: file.name })));
      event.target.value = '';
    });
    $('#new-folder').addEventListener('click', newFolder);
    $('#view-toggle').addEventListener('click', () => {
      state.view = state.view === 'grid' ? 'list' : 'grid';
      store('webclient-view', state.view);
      render();
    });
    const search = $('#search');
    search.addEventListener('input', () => {
      if (state.results) {
        state.results = null;
        state.query = '';
      }
      state.filter = search.value.trim().toLowerCase();
      render();
    });
    search.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        searchEverywhere(search.value);
      } else if (event.key === 'Escape' && search.value) {
        search.value = '';
        state.filter = '';
        state.results = null;
        render();
      }
    });
    $('#selection-clear').addEventListener('click', () => {
      state.selected.clear();
      updateSelection();
      render();
    });
    const selected = () => [...state.selected.values()];
    $('#selection-download').addEventListener('click', () => downloadZip(selected()));
    $('#selection-move').addEventListener('click', () => moveOrCopy(selected()));
    $('#selection-share').addEventListener('click', () => share(selected()));
    $('#selection-delete').addEventListener('click', () => remove(selected()));
    WC.bindDropTarget($('#sheet'), { accepts: () => can('add') && !state.results, onFiles: upload });
    window.addEventListener('popstate', (event) => {
      const path = (event.state && event.state.path) || new URLSearchParams(location.search).get('path') || '/';
      load(path);
    });
    document.addEventListener('languagechange', () => {
      renderTabs();
      render();
      updateSelection();
    });
  }

  WC.ready.then(() => {
    bindControls();
    if (!isShare) WC.refreshTokenEvery(2 * 60 * 60 * 1000);
    load(state.cwd, { replace: true });
  });
})();
