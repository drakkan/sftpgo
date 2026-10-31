// Upload queue and the panel that shows it. Files go one at a time, each as its own
// XMLHttpRequest whose body is the File: the Android app watches exactly that to keep
// running in the background, and to show its progress notification.
(function () {
  'use strict';
  const { h, t, icon, csrfToken, request, formatSize } = WC;

  function collectEntry(entry, prefix, found) {
    return new Promise((resolve) => {
      if (entry.isFile) {
        entry.file((file) => {
          found.push({ file, relative: prefix + file.name });
          resolve();
        }, () => resolve());
        return;
      }
      const reader = entry.createReader();
      const readAll = () => reader.readEntries(async (batch) => {
        if (!batch.length) {
          resolve();
          return;
        }
        for (const child of batch) await collectEntry(child, `${prefix}${entry.name}/`, found);
        readAll();
      }, () => resolve());
      readAll();
    });
  }

  // Dropped folders only keep their structure through the entries API.
  async function filesFromDrop(dataTransfer) {
    const entries = [...dataTransfer.items]
      .filter((item) => item.kind === 'file')
      .map((item) => (item.webkitGetAsEntry ? item.webkitGetAsEntry() : null));
    if (entries.length && entries.every(Boolean)) {
      const found = [];
      for (const entry of entries) await collectEntry(entry, '', found);
      return found;
    }
    return [...dataTransfer.files].map((file) => ({ file, relative: file.name }));
  }

  class TransferQueue {
    constructor({ pingURL, keepAlive, onFileDone }) {
      this.items = [];
      this.active = null;
      this.onFileDone = onFileDone;
      this.pingURL = pingURL;
      this.keepAlive = keepAlive;
      this.timer = null;
      this.buildPanel();
      window.addEventListener('beforeunload', (event) => {
        if (this.isBusy()) event.preventDefault();
      });
      document.addEventListener('languagechange', () => this.items.forEach((item) => this.paint(item)));
    }

    buildPanel() {
      this.title = h('span');
      this.list = h('ul.dock-list');
      this.closeButton = h('button.iconbutton', {
        type: 'button',
        ariaLabel: t('general.close'),
        onclick: () => this.dismiss(),
      }, icon('x'));
      this.panel = h('aside.dock', { hidden: true }, h('div.dock-head', null, this.title, this.closeButton), this.list);
      document.body.append(this.panel);
    }

    isBusy() {
      return this.items.some((item) => item.state === 'waiting' || item.state === 'running');
    }

    add(entries) {
      for (const { file, url, label } of entries) {
        const item = { file, url, label, state: 'waiting', loaded: 0 };
        item.status = h('span.dock-status');
        item.fill = h('div.meter-fill');
        item.action = h('button.iconbutton', {
          type: 'button',
          ariaLabel: t('client.upload_cancel'),
          onclick: () => this.cancel(item),
        }, icon('x'));
        item.row = h('li.dock-item', null,
          h('span.dock-name', { title: label }, label),
          item.action,
          h('div.meter', null, item.fill),
          item.status);
        this.items.push(item);
        this.list.append(item.row);
        this.paint(item);
      }
      this.panel.hidden = false;
      this.updateTitle();
      this.startKeepAlive();
      this.next();
    }

    paint(item) {
      const percent = item.file.size ? Math.round((100 * item.loaded) / item.file.size) : 0;
      const texts = {
        waiting: t('client.upload_waiting'),
        running: `${formatSize(item.loaded)} / ${formatSize(item.file.size)}`,
        done: t('client.upload_done'),
        failed: item.error || t('fs.upload.err_generic'),
        cancelled: t('client.upload_cancelled'),
      };
      item.status.textContent = texts[item.state];
      item.fill.style.width = `${item.state === 'done' ? 100 : percent}%`;
      item.row.classList.toggle('is-failed', item.state === 'failed');
      item.action.hidden = item.state !== 'waiting' && item.state !== 'running';
    }

    updateTitle() {
      const finished = this.items.filter((item) => item.state === 'done').length;
      this.title.textContent = t('fs.uploading', { idx: finished, total: this.items.length });
      this.closeButton.hidden = this.isBusy();
    }

    next() {
      if (this.active) return;
      const item = this.items.find((candidate) => candidate.state === 'waiting');
      this.updateTitle();
      if (!item) {
        this.stopKeepAlive();
        const failed = this.items.some((candidate) => candidate.state === 'failed');
        if (!failed && this.items.length) {
          window.setTimeout(() => {
            if (!this.isBusy()) this.dismiss();
          }, 4000);
        }
        return;
      }
      this.send(item);
    }

    send(item) {
      const xhr = new XMLHttpRequest();
      item.xhr = xhr;
      item.state = 'running';
      this.active = item;
      this.paint(item);
      xhr.open('POST', item.url);
      xhr.setRequestHeader('X-CSRF-TOKEN', csrfToken());
      if (item.file.lastModified) xhr.setRequestHeader('X-SFTPGO-MTIME', String(item.file.lastModified));
      xhr.upload.addEventListener('progress', (event) => {
        if (event.lengthComputable) {
          item.loaded = event.loaded;
          this.paint(item);
        }
      });
      xhr.addEventListener('loadend', () => {
        if (item.state === 'running') {
          if (xhr.status >= 200 && xhr.status < 300) {
            item.state = 'done';
            item.loaded = item.file.size;
          } else {
            item.state = 'failed';
            item.error = this.describe(xhr);
          }
        }
        this.active = null;
        this.paint(item);
        if (item.state === 'done' && this.onFileDone) this.onFileDone(item);
        // Not synchronously: the Android app's own listener on this request runs after this
        // one, and must report the end of this file before the next one starts.
        window.setTimeout(() => this.next(), 0);
      });
      xhr.send(item.file);
    }

    describe(xhr) {
      let key = 'fs.upload.err_generic';
      if (xhr.status === 403) key = 'fs.upload.err_403';
      else if (xhr.status === 429) key = 'fs.upload.err_429';
      else if (xhr.status === 413) key = 'general.err_quota_read';
      try {
        const message = JSON.parse(xhr.responseText).message;
        if (message && i18next.exists(message)) key = message;
      } catch {
        // Not JSON: keep the message for the status.
      }
      return t(key);
    }

    cancel(item) {
      if (item.state === 'running') {
        item.state = 'cancelled';
        item.xhr.abort();
      } else if (item.state === 'waiting') {
        item.state = 'cancelled';
        this.paint(item);
        this.updateTitle();
      }
    }

    dismiss() {
      if (this.isBusy()) return;
      this.items = [];
      this.list.replaceChildren();
      this.panel.hidden = true;
    }

    startKeepAlive() {
      if (this.timer || !this.pingURL || !this.keepAlive) return;
      this.timer = window.setInterval(() => {
        request(this.pingURL).catch(() => {});
      }, this.keepAlive);
    }

    stopKeepAlive() {
      window.clearInterval(this.timer);
      this.timer = null;
    }
  }

  async function confirmOverwrite(names, existing) {
    const conflicts = names.filter((name) => existing.includes(name));
    if (!conflicts.length) return true;
    return WC.dialog({
      title: t('client.upload_conflict'),
      body: [
        h('p', null, t('fs.upload.overwrite_text')),
        h('ul', null, conflicts.map((name) => h('li', null, name))),
      ],
      actions: [
        { label: t('client.cancel'), value: false },
        { label: t('client.overwrite'), value: true, kind: 'danger' },
      ],
    });
  }

  function bindDropTarget(target, { accepts, onFiles }) {
    let depth = 0;
    const carriesFiles = (event) => [...event.dataTransfer.types].includes('Files');
    target.addEventListener('dragenter', (event) => {
      if (!carriesFiles(event) || !accepts()) return;
      event.preventDefault();
      depth += 1;
      target.classList.add('is-receiving');
    });
    target.addEventListener('dragover', (event) => {
      if (carriesFiles(event) && accepts()) event.preventDefault();
    });
    target.addEventListener('dragleave', (event) => {
      if (!carriesFiles(event)) return;
      depth = Math.max(0, depth - 1);
      if (!depth) target.classList.remove('is-receiving');
    });
    target.addEventListener('drop', async (event) => {
      if (!carriesFiles(event) || !accepts()) return;
      event.preventDefault();
      depth = 0;
      target.classList.remove('is-receiving');
      onFiles(await filesFromDrop(event.dataTransfer));
    });
  }

  Object.assign(WC, { TransferQueue, confirmOverwrite, bindDropTarget });
})();
