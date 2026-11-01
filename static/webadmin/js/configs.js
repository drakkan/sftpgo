// The buttons of the SMTP section. The forms themselves post normally.
(function () {
  'use strict';
  const { $, t, request, toast, confirmDialog, errorText } = WC;

  const field = (name) => $(`[name="${name}"]`).value.trim();

  function oauth2Values() {
    return {
      provider: Number(field('smtp_oauth2_provider')),
      tenant: field('smtp_oauth2_tenant'),
      client_id: field('smtp_oauth2_client_id'),
      client_secret: field('smtp_oauth2_client_secret'),
      refresh_token: field('smtp_oauth2_refresh_token'),
    };
  }

  async function sendTest() {
    const recipient = $('#smtp-recipient').value.trim();
    if (!recipient) {
      toast('error', t('smtp.recipient_required'));
      return;
    }
    try {
      await request($('#configs').dataset.test, {
        method: 'POST',
        json: {
          host: field('smtp_host'),
          port: Number(field('smtp_port')),
          from: field('smtp_from'),
          user: field('smtp_username'),
          password: field('smtp_password'),
          auth_type: Number(field('smtp_auth')),
          encryption: Number(field('smtp_encryption')),
          domain: field('smtp_domain'),
          debug: $('[name=smtp_debug]').checked ? 1 : 0,
          oauth2: oauth2Values(),
          recipient,
        },
      });
      toast('success', t('smtp.test_ok'));
    } catch (error) {
      toast('error', errorText(error, 'smtp.test_error'));
    }
  }

  async function startOAuth2() {
    const confirmed = await confirmDialog({ title: t('smtp.oauth2_token'), message: t('smtp.oauth2_question'), confirm: t('general.confirm') });
    if (!confirmed) return;
    try {
      const { data } = await request($('#configs').dataset.oauth2, {
        method: 'POST',
        json: { ...oauth2Values(), base_redirect_url: window.location.origin },
      });
      window.open(data.message, '_blank', 'noopener');
    } catch (error) {
      toast('error', errorText(error, 'smtp.oauth2_flow_error'));
    }
  }

  WC.ready.then(() => {
    $('#smtp-test').addEventListener('click', sendTest);
    $('#oauth2-get').addEventListener('click', startOAuth2);
  });
})();
