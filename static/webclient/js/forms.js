// Lists of values in a form, such as public keys or the paths of a share. Each value is a
// field with the same name, which is how the server reads them.
(function () {
  'use strict';
  const { $$, h, t, icon } = WC;

  function bindRepeat(holder) {
    const { repeat: name, type, inputType, placeholder } = holder.dataset;

    function newField(value = '') {
      if (type === 'textarea') {
        return h('textarea.textarea.textarea-code', {
          name,
          value,
          spellcheck: false,
          placeholder: placeholder ? t(placeholder) : undefined,
        });
      }
      return h('input.input', { name, type: inputType || 'text', value, placeholder: placeholder ? t(placeholder) : undefined });
    }

    function wrap(field) {
      const row = h('div.repeat-row', null, h('button.iconbutton', {
        type: 'button',
        ariaLabel: t('general.delete'),
        title: t('general.delete'),
        onclick: () => row.remove(),
      }, icon('trash-2')));
      row.prepend(field);
      return row;
    }

    const rows = h('div.repeat');
    for (const field of [...holder.children]) rows.append(wrap(field));
    const add = h('button.button', {
      type: 'button',
      onclick: () => {
        const field = newField();
        rows.append(wrap(field));
        field.focus();
      },
    }, icon('plus'), h('span', null, t('general.add')));
    holder.replaceChildren(rows, add);
    if (holder.dataset.minimum && !rows.children.length) rows.append(wrap(newField()));
    holder.closest('form').addEventListener('submit', () => {
      for (const field of $$(`[name="${name}"]`, holder)) {
        if (!field.value.trim()) field.closest('.repeat-row').remove();
      }
    });
  }

  WC.ready.then(() => {
    $$('[data-repeat]').forEach(bindRepeat);
  });
})();
