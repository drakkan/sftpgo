// The text editor. Saving replaces the file with a plain upload of the new contents.
(function () {
  'use strict';
  const { $, t, request, toast } = WC;

  const page = $('#editor-page');
  const data = page.dataset;
  const readOnly = data.readonly === 'true';

  WC.ready.then(() => {
    const dot = data.name.lastIndexOf('.');
    const options = {
      oneDark: document.documentElement.dataset.theme === 'dark',
      fileExt: dot > 0 ? data.name.slice(dot + 1).toLowerCase() : '',
    };
    if (readOnly) options.readOnly = true;
    if (data.nonce) options.cspNonce = data.nonce;
    const view = cm6.createEditorView(cm6.createEditorState($('#source').value, options), $('#editor'));
    let saved = view.state.doc.toString();

    $('#back-tab').href = `${data.files}?path=${encodeURIComponent(data.dir)}`;
    window.setInterval(() => request(data.ping).catch(() => {}), 10 * 60 * 1000);
    if (readOnly) return;

    const button = $('#save');
    async function save() {
      button.disabled = true;
      const content = view.state.doc.toString();
      try {
        await request(`${data.file}?path=${encodeURIComponent(data.path)}`, { method: 'POST', body: new Blob([content]) });
        saved = content;
        toast('success', t('client.saved'));
      } catch (error) {
        let key = 'fs.save.err_generic';
        if (error.status === 403) key = 'fs.save.err_403';
        else if (error.status === 429) key = 'fs.save.err_429';
        toast('error', t(key));
      }
      button.disabled = false;
    }

    button.addEventListener('click', save);
    document.addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
        event.preventDefault();
        save();
      }
    });
    window.addEventListener('beforeunload', (event) => {
      if (view.state.doc.toString() !== saved) event.preventDefault();
    });
  });
})();
