// The page for shares that only accept uploads.
(function () {
  'use strict';
  const { $, t, toast } = WC;

  const base = $('#share-upload').dataset.base;

  WC.ready.then(() => {
    const queue = new WC.TransferQueue({
      onFileDone: () => {
        if (!queue.isBusy()) toast('success', t('fs.upload.success'));
      },
    });
    const send = (found) => {
      if (!found.length) {
        toast('error', t('fs.upload_no_files'));
        return;
      }
      queue.add(found.map(({ file, relative }) => ({
        file,
        label: relative,
        url: `${base}/${encodeURIComponent(relative)}?mkdir_parents=true`,
      })));
    };
    const zone = $('#dropzone');
    const picker = $('#picker');
    zone.addEventListener('click', () => picker.click());
    picker.addEventListener('change', () => {
      send([...picker.files].map((file) => ({ file, relative: file.name })));
      picker.value = '';
    });
    WC.bindDropTarget(zone, { accepts: () => true, onFiles: send });
  });
})();
