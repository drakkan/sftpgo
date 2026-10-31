// Two-factor setup: enrol an authenticator app, pick protocols, handle recovery codes.
(function () {
  'use strict';
  const { $, $$, h, t, request, toast, dialog, confirmDialog, errorText } = WC;

  const page = $('#mfa');
  const data = page.dataset;
  const required = (data.required || '').split(' ').filter(Boolean);

  function selectedProtocols() {
    return $$('input[name=protocol]:checked').map((input) => input.value);
  }

  function checkProtocols(protocols) {
    if (!protocols.length) {
      toast('error', t('2fa.no_protocol'));
      return false;
    }
    if (required.some((protocol) => !protocols.includes(protocol))) {
      toast('error', t('2fa.required_protocols', { val: required.join(', ') }));
      return false;
    }
    return true;
  }

  // Saving can end the session when the setup was mandatory, and the login page takes over.
  async function afterSave() {
    window.location.reload();
  }

  async function saveProtocols() {
    const protocols = selectedProtocols();
    if (!checkProtocols(protocols)) return;
    try {
      await request(data.save, { method: 'POST', json: { enabled: true, protocols } });
      toast('success', t('general.config_saved'));
    } catch (error) {
      toast('error', errorText(error, '2fa.save_err'));
    }
  }

  async function enrol() {
    const protocols = selectedProtocols();
    if (!checkProtocols(protocols)) return;
    if (data.enabled === 'true') {
      const confirmed = await confirmDialog({
        title: t('2fa.generate'),
        message: t('2fa.generate_question'),
        confirm: t('general.confirm'),
        danger: true,
      });
      if (!confirmed) return;
    }
    const configName = $('#config').value;
    let secret;
    try {
      ({ data: secret } = await request(data.generate, { method: 'POST', json: { config_name: configName } }));
    } catch (error) {
      toast('error', errorText(error, '2fa.auth_secret_gen_err'));
      return;
    }
    const passcode = h('input.input', { type: 'text', inputMode: 'numeric', autocomplete: 'one-time-code', required: true });
    const problem = h('p.field-error', { hidden: true });
    const confirmed = await dialog({
      title: t('2fa.setup_title'),
      body: [
        h('p.field-help', null, t('2fa.setup_msg')),
        h('img.qr', { src: `data:image/png;base64,${secret.qr_code}`, alt: t('general.qr_code') }),
        h('p.field-help', null, t('2fa.setup_help')),
        h('p.secret', null, secret.secret),
        h('label.field', null, h('span.field-label', null, t('login.auth_code')), passcode),
        problem,
      ],
      actions: [
        { label: t('client.cancel'), value: false },
        { label: t('general.verify'), kind: 'primary', submit: true, value: () => passcode.value.trim() },
      ],
      onOpen: () => passcode.focus(),
    });
    if (!confirmed) return;
    try {
      await request(data.validate, { method: 'POST', json: { config_name: configName, passcode: confirmed, secret: secret.secret } });
    } catch (error) {
      toast('error', t('2fa.auth_code_invalid'));
      return;
    }
    try {
      await request(data.save, {
        method: 'POST',
        json: { enabled: true, config_name: configName, protocols, secret: { status: 'Plain', payload: secret.secret } },
      });
      await afterSave();
    } catch (error) {
      toast('error', errorText(error, '2fa.save_err'));
    }
  }

  async function disable() {
    const confirmed = await confirmDialog({
      title: t('2fa.disable_msg'),
      message: t('2fa.disable_question'),
      confirm: t('general.disable_confirm_btn'),
      danger: true,
    });
    if (!confirmed) return;
    try {
      await request(data.save, { method: 'POST', json: { enabled: false } });
      await afterSave();
    } catch (error) {
      toast('error', errorText(error, '2fa.save_err'));
    }
  }

  function showCodes(title, codes) {
    return dialog({
      title,
      body: [
        h('p.field-help', null, t('2fa.recovery_codes_msg2')),
        h('ul.codes', null, codes.map((entry) => h(`li${entry.used ? '.is-used' : ''}`, null, entry.code))),
      ],
      actions: [{ label: t('general.close'), value: true, kind: 'primary' }],
      wide: true,
    });
  }

  async function viewCodes() {
    try {
      const { data: codes } = await request(data.codes);
      await showCodes(t('2fa.recovery_codes'), codes || []);
    } catch (error) {
      toast('error', errorText(error, '2fa.recovery_codes_get_err'));
    }
  }

  async function newCodes() {
    const confirmed = await confirmDialog({
      title: t('2fa.recovery_codes_generate'),
      message: t('2fa.recovery_codes_msg3'),
      confirm: t('general.confirm'),
      danger: true,
    });
    if (!confirmed) return;
    try {
      const { data: codes } = await request(data.codes, { method: 'POST' });
      await showCodes(t('2fa.new_recovery_codes'), (codes || []).map((code) => (typeof code === 'string' ? { code } : code)));
    } catch (error) {
      toast('error', errorText(error, '2fa.recovery_codes_gen_err'));
    }
  }

  WC.ready.then(() => {
    $('#generate').addEventListener('click', enrol);
    const bind = (selector, handler) => {
      const button = $(selector);
      if (button) button.addEventListener('click', handler);
    };
    bind('#save-protocols', saveProtocols);
    bind('#disable', disable);
    bind('#view-codes', viewCodes);
    bind('#new-codes', newCodes);
  });
})();
