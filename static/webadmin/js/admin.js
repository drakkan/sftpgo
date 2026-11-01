// Parts shared by the WebAdmin pages: data tables, rows of repeated fields, fields that
// depend on another field, and the navigation on small screens. Runs next to the WebClient
// helpers in core.js, as a classic script so that it can carry a CSP nonce.
(function () {
  'use strict';
  const { $, $$, h, t, icon, request, toast, confirmDialog, errorText, openMenu } = WC;

  const page = document.body.dataset;
  const permissions = (page.perms || '').split(' ').filter(Boolean);
  const can = (permission) => permissions.includes('*') || permissions.includes(permission);
  const pageSizes = [25, 50, 100, 500];
  const sizeKey = 'webadmin-page-size';

  function storedPageSize() {
    try {
      const saved = Number(localStorage.getItem(sizeKey));
      return pageSizes.includes(saved) ? saved : pageSizes[0];
    } catch {
      return pageSizes[0];
    }
  }

  function storePageSize(size) {
    try {
      localStorage.setItem(sizeKey, String(size));
    } catch {
      // The size then lasts until this page is left.
    }
  }

  const compare = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' }).compare;

  function sortValue(column, row) {
    const value = column.sort ? column.sort(row) : column.value ? column.value(row) : row[column.key];
    return value === undefined || value === null ? '' : value;
  }

  function searchText(columns, row) {
    return columns.map((column) => {
      if (column.search === false) return '';
      const value = column.value ? column.value(row) : row[column.key];
      return value === undefined || value === null ? '' : String(value);
    }).join(' ').toLowerCase();
  }

  // A table that loads its rows once, then searches, sorts and pages in the browser.
  // Columns: { key, title, value(row), sort(row), render(row), wrap, search }.
  function table(options) {
    const { root, columns, load, rowId, actions, tools, bulk } = options;
    const state = {
      rows: [],
      filter: '',
      sort: options.sortBy || columns[0].key,
      descending: Boolean(options.descending),
      page: 0,
      size: storedPageSize(),
      selected: new Set(),
      loading: true,
      failed: false,
    };
    const selectable = Boolean(bulk);
    const search = h('input.input.table-search', {
      type: 'search',
      placeholder: t('general.search'),
      ariaLabel: t('general.search'),
      oninput: () => {
        state.filter = search.value.trim().toLowerCase();
        state.page = 0;
        draw();
      },
    });
    const bar = h('div.bulkbar', { hidden: true });
    const tbody = h('tbody');
    const headRow = h('tr');
    const foot = h('div.table-foot');
    const toolEnd = h('div.table-tools-end');
    const grid = h('table.datagrid', null, h('thead', null, headRow), tbody);
    root.replaceChildren(
      h('div.table-tools', null, search, toolEnd),
      bar,
      h('div.table-wrap', null, grid),
      foot,
    );

    const column = (key) => columns.find((entry) => entry.key === key) || columns[0];

    function visibleRows() {
      const rows = state.filter ? state.rows.filter((row) => searchText(columns, row).includes(state.filter)) : [...state.rows];
      const current = column(state.sort);
      rows.sort((a, b) => {
        const left = sortValue(current, a);
        const right = sortValue(current, b);
        const order = typeof left === 'number' && typeof right === 'number' ? left - right : compare(String(left), String(right));
        return state.descending ? -order : order;
      });
      return rows;
    }

    function drawHead(rows) {
      const cells = [];
      if (selectable) {
        const shown = rows.slice(state.page * state.size, (state.page + 1) * state.size);
        const all = h('input', {
          type: 'checkbox',
          ariaLabel: t('general.actions'),
          checked: shown.length > 0 && shown.every((row) => state.selected.has(rowId(row))),
          onchange: () => {
            for (const row of shown) {
              if (all.checked) state.selected.add(rowId(row));
              else state.selected.delete(rowId(row));
            }
            draw();
          },
        });
        cells.push(h('th.col-check', { scope: 'col' }, all));
      }
      for (const entry of columns) {
        const active = state.sort === entry.key;
        const sortable = entry.sortable !== false;
        cells.push(h('th', {
          scope: 'col',
          ariaSort: active ? (state.descending ? 'descending' : 'ascending') : undefined,
        }, sortable ? h('button.head-sort', {
          type: 'button',
          onclick: () => {
            state.descending = active ? !state.descending : false;
            state.sort = entry.key;
            state.page = 0;
            draw();
          },
        }, entry.title(), active ? icon(state.descending ? 'arrow-down' : 'arrow-up') : null) : entry.title()));
      }
      if (actions) cells.push(h('th.col-actions', { scope: 'col' }, h('span.sr', null, t('general.actions'))));
      headRow.replaceChildren(...cells);
    }

    function drawBody(rows) {
      const span = columns.length + (selectable ? 1 : 0) + (actions ? 1 : 0);
      if (state.loading || state.failed || !rows.length) {
        const text = state.loading ? t('general.loading') : state.failed ? t('general.error500') : t('datatable.no_records');
        tbody.replaceChildren(h('tr', null, h('td.muted', { colSpan: span }, text)));
        return;
      }
      tbody.replaceChildren(...rows.slice(state.page * state.size, (state.page + 1) * state.size).map((row) => {
        const id = selectable ? rowId(row) : '';
        const selected = selectable && state.selected.has(id);
        const cells = [];
        if (selectable) {
          cells.push(h('td.col-check', null, h('input', {
            type: 'checkbox',
            ariaLabel: id,
            checked: selected,
            onchange: (event) => {
              if (event.target.checked) state.selected.add(id);
              else state.selected.delete(id);
              draw();
            },
          })));
        }
        for (const entry of columns) {
          const content = entry.render ? entry.render(row) : entry.value ? entry.value(row) : row[entry.key];
          cells.push(h(`td${entry.wrap ? '.col-wrap' : ''}`, null, content === undefined ? '' : content));
        }
        if (actions) {
          const button = h('button.iconbutton', {
            type: 'button',
            ariaLabel: t('general.actions'),
            title: t('general.actions'),
            ariaHaspopup: 'menu',
            onclick: () => openMenu(button, actions(row)),
          }, icon('ellipsis'));
          cells.push(h('td.col-actions', null, button));
        }
        return h('tr', { dataset: selected ? { selected: '' } : {} }, ...cells);
      }));
    }

    function drawFoot(total) {
      const pages = Math.max(1, Math.ceil(total / state.size));
      state.page = Math.min(state.page, pages - 1);
      const first = total ? state.page * state.size + 1 : 0;
      const last = Math.min(total, (state.page + 1) * state.size);
      const info = t(total ? 'datatable.info' : 'datatable.info_empty')
        .replace('_START_', first).replace('_END_', last).replace('_TOTAL_', total);
      const sizes = h('select.select', {
        ariaLabel: t('datatable.info'),
        onchange: () => {
          state.size = Number(sizes.value);
          storePageSize(state.size);
          state.page = 0;
          draw();
        },
      }, pageSizes.map((size) => h('option', { value: size, selected: size === state.size }, String(size))));
      foot.replaceChildren(h('span', null, info), h('div.table-pager', null, sizes,
        h('button.iconbutton', {
          type: 'button', ariaLabel: t('general.previous'), disabled: state.page === 0,
          onclick: () => { state.page -= 1; draw(); },
        }, icon('chevron-left')),
        h('span', null, ` ${state.page + 1} / ${pages} `),
        h('button.iconbutton', {
          type: 'button', ariaLabel: t('general.next'), disabled: state.page >= pages - 1,
          onclick: () => { state.page += 1; draw(); },
        }, icon('chevron-right'))));
    }

    function drawBulk(rows) {
      if (!selectable) return;
      const count = state.selected.size;
      bar.hidden = count === 0;
      if (!count) return;
      const clear = () => { state.selected.clear(); draw(); };
      const selectAll = count < rows.length ? h('button.button', {
        type: 'button',
        onclick: () => {
          for (const row of rows) state.selected.add(rowId(row));
          draw();
        },
      }, bulk.selectAll ? bulk.selectAll(rows.length) : t('general.actions')) : null;
      bar.replaceChildren(
        h('span', null, t('general.selected_items', { count })),
        ...(selectAll ? [selectAll] : []),
        ...bulk.actions.map((action) => h(`button.button${action.danger ? '.button-danger' : ''}`, {
          type: 'button',
          onclick: () => action.run([...state.selected]),
        }, icon(action.icon), h('span', null, action.label()))),
        h('button.iconbutton', { type: 'button', ariaLabel: t('general.close'), onclick: clear }, icon('x')),
      );
    }

    function draw() {
      const rows = visibleRows();
      drawHead(rows);
      drawBody(rows);
      drawFoot(rows.length);
      drawBulk(rows);
    }

    async function reload() {
      state.loading = true;
      state.failed = false;
      draw();
      try {
        state.rows = await load();
      } catch (error) {
        state.rows = [];
        state.failed = true;
        toast('error', errorText(error));
      }
      state.loading = false;
      state.selected.clear();
      draw();
    }

    function drawTools() {
      toolEnd.replaceChildren(...(tools ? tools(api) : []));
    }

    const api = { reload, draw, refreshTools: drawTools };
    document.addEventListener('languagechange', () => {
      search.placeholder = t('general.search');
      drawTools();
      draw();
    });
    drawTools();
    reload();
    return api;
  }

  function badge(text, kind) {
    return h(`span.badge${kind ? `.badge-${kind}` : ''}`, null, text);
  }

  function statusBadge(active) {
    return active ? badge(t('general.active'), 'ok') : badge(t('general.inactive'), 'off');
  }

  function linkButton(label, href, iconName) {
    return h('a.button.button-primary', { href }, icon(iconName || 'plus'), h('span', null, label));
  }

  function plainButton(label, iconName, onclick) {
    return h('button.button', { type: 'button', onclick }, icon(iconName), h('span', null, label));
  }

  // Asks, deletes, then refreshes: every list removes rows the same way.
  async function removeRow({ url, name, list, fallback }) {
    const confirmed = await confirmDialog({
      title: t('general.delete'),
      message: t('general.delete_confirm', { name }),
      confirm: t('general.delete_confirm_btn'),
      danger: true,
    });
    if (!confirmed) return;
    try {
      await request(url, { method: 'DELETE' });
      list.reload();
    } catch (error) {
      toast('error', errorText(error, fallback || 'general.delete_error_generic'));
    }
  }

  // Rows of repeated fields. The template holds one row, and each field names itself with
  // data-field: on submit the server expects group[index][field]. The saved rows come as
  // <i data-item> elements, with one data attribute per field.
  function bindRows(holder) {
    const group = holder.dataset.rows;
    const ordered = 'ordered' in holder.dataset;
    const template = $('template', holder);
    const rows = h('div.rows');

    function renumber() {
      [...rows.children].forEach((row, index) => {
        for (const field of $$('[data-field]', row)) {
          const suffix = 'multi' in field.dataset ? '[]' : '';
          field.name = `${group}[${index}][${field.dataset.field}]${suffix}`;
        }
      });
    }

    function fill(row, values) {
      for (const field of $$('[data-field]', row)) {
        const value = values[field.dataset.field];
        if (value === undefined) continue;
        if (field.type === 'checkbox') {
          if ('multi' in field.dataset) field.checked = value.split(',').includes(field.value);
          else field.checked = value === 'true' || value === field.value;
        } else {
          field.value = value;
        }
      }
    }

    function addRow(values) {
      const fields = h('div.row-fields');
      fields.append(template.content.cloneNode(true));
      const buttons = h('div.row-tools');
      const row = h('div.row', null, fields, buttons);
      if (ordered) {
        const move = (forward) => {
          const sibling = forward ? row.nextElementSibling : row.previousElementSibling;
          if (sibling) {
            if (forward) sibling.after(row);
            else sibling.before(row);
            renumber();
          }
        };
        buttons.append(
          h('button.iconbutton', { type: 'button', ariaLabel: t('general.previous'), onclick: () => move(false) }, icon('arrow-up')),
          h('button.iconbutton', { type: 'button', ariaLabel: t('general.next'), onclick: () => move(true) }, icon('arrow-down')),
        );
      }
      buttons.append(h('button.iconbutton', {
        type: 'button',
        ariaLabel: t('general.delete'),
        title: t('general.delete'),
        onclick: () => {
          row.remove();
          renumber();
        },
      }, icon('trash-2')));
      if (values) fill(row, values);
      rows.append(row);
      WC.translate(row);
      setupDependents(row);
      renumber();
      return row;
    }

    const items = $$('[data-item]', holder);
    const saved = items.map((item) => ({ ...item.dataset }));
    items.forEach((item) => item.remove());
    template.remove();
    const add = h('button.button', {
      type: 'button',
      onclick: () => {
        const row = addRow();
        const first = $('input,select,textarea', row);
        if (first) first.focus();
      },
    }, icon('plus'), h('span', null, t('general.add')));
    holder.append(rows, h('div', null, add));
    saved.forEach(addRow);
    if ('minimum' in holder.dataset && !saved.length) addRow();
  }

  // data-show-when="field=value,value": shown only while the named field has one of the
  // values. The field is looked up in the same row first, then in the page.
  function fieldValue(name, scope) {
    const near = scope.closest('.row');
    const inRow = near ? $$('[data-field]', near).filter((field) => field.dataset.field === name) : [];
    const fields = inRow.length ? inRow : $$(`[name="${name}"]`);
    const field = fields.find((entry) => entry.type !== 'radio' || entry.checked) || fields[0];
    if (!field) return '';
    if (field.type === 'checkbox') return field.checked ? 'on' : '';
    return field.value;
  }

  function setupDependents(scope = document) {
    for (const element of $$('[data-show-when]', scope)) {
      const conditions = element.dataset.showWhen.split(';').map((condition) => {
        const [name, values] = condition.split('=');
        return { name, values: values.split(',') };
      });
      const refresh = () => {
        element.hidden = !conditions.every(({ name, values }) => values.includes(fieldValue(name, element)));
      };
      for (const { name } of conditions) {
        const near = element.closest('.row');
        const fields = (near ? $$('[data-field]', near).filter((field) => field.dataset.field === name) : []);
        for (const field of fields.length ? fields : $$(`[name="${name}"]`)) field.addEventListener('change', refresh);
      }
      refresh();
    }
  }

  function pad(value) {
    return String(value).padStart(2, '0');
  }

  function localInputValue(date) {
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function serverDateValue(date) {
    return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} `
      + `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
  }

  // The server stores UTC and the browser picks local time. The visible input has no name,
  // and a hidden field next to it carries what the server reads.
  function setupDates() {
    for (const input of $$('input[data-date-for]')) {
      const target = $(`input[name="${input.dataset.dateFor}"]`);
      const stored = Number(input.dataset.ms) || (target.value ? Date.parse(`${target.value.replace(' ', 'T')}Z`) : 0);
      if (stored) {
        input.value = localInputValue(new Date(stored));
        target.value = serverDateValue(new Date(stored));
      }
      input.addEventListener('change', () => {
        target.value = input.value ? serverDateValue(new Date(input.value)) : '';
      });
    }
  }

  // The server rejects an empty number, and an empty field here always means zero.
  function setupNumbers() {
    for (const form of $$('form')) {
      form.addEventListener('submit', () => {
        for (const input of $$('input[type=number]:not([data-blank])', form)) {
          if (input.value === '') input.value = '0';
        }
      });
    }
  }

  function setupTabs() {
    for (const strip of $$('[data-tabs]')) {
      const buttons = $$('button[data-tab]', strip);
      const show = (name) => {
        for (const button of buttons) {
          button.setAttribute('aria-selected', String(button.dataset.tab === name));
          $(`#${button.dataset.tab}`).hidden = button.dataset.tab !== name;
        }
        strip.dispatchEvent(new CustomEvent('tabchange', { detail: name }));
      };
      for (const button of buttons) button.addEventListener('click', () => show(button.dataset.tab));
      show(strip.dataset.tabs || buttons[0].dataset.tab);
    }
  }

  function setupRail() {
    const button = $('[data-rail-toggle]');
    if (!button) return;
    button.addEventListener('click', () => {
      const open = $('#rail').classList.toggle('is-open');
      button.setAttribute('aria-expanded', String(open));
    });
  }

  function setupCopy() {
    for (const button of $$('[data-copy]')) {
      button.addEventListener('click', async () => {
        try {
          const source = $(button.dataset.copy);
          await navigator.clipboard.writeText(('value' in source ? source.value : source.textContent).trim());
          toast('success', t('general.copied'));
        } catch {
          toast('error', t('general.error500'));
        }
      });
    }
  }

  WC.ready.then(() => {
    setupRail();
    $$('[data-rows]').forEach(bindRows);
    setupDependents();
    setupDates();
    setupNumbers();
    setupTabs();
    setupCopy();
  });

  window.WA = { page, can, table, badge, statusBadge, linkButton, plainButton, removeRow, setupDependents, compare };
})();
