// The expiration of a share. The browser's picker works in local time, the server reads UTC.
(function () {
  'use strict';
  const { $ } = WC;

  function toLocalInput(milliseconds) {
    const date = new Date(milliseconds);
    const pad = (value) => String(value).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function toServerFormat(value) {
    return new Date(value).toISOString().slice(0, 19).replace('T', ' ');
  }

  WC.ready.then(() => {
    const holder = $('#expiration');
    const picker = $('#expiration-picker');
    const hidden = $('input[name=expiration_date]');
    const existing = Number(holder.dataset.value);
    if (existing > 0) picker.value = toLocalInput(existing);
    $('#share').addEventListener('submit', () => {
      hidden.value = picker.value ? toServerFormat(picker.value) : '';
    });
  });
})();
