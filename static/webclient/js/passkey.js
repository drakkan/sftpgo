// Passkeys: the browser side of WebAuthn, and the sign-in buttons. A sign in ends in a normal form
// post, as the server answers it with the same redirects and error pages as a password.
(function () {
  'use strict';
  const { $, h, t, request, toast, errorText } = WC;

  const toBytes = (text) => {
    const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  };

  const toText = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  const decodeList = (list) => list && list.map((entry) => ({ ...entry, id: toBytes(entry.id) }));

  // Browsers refuse a domain that is an IP address, and offer no WebAuthn on plain http.
  function supported() {
    const isIP = /^[\d.]+$/.test(location.hostname) || location.hostname.includes(':');
    return Boolean(window.PublicKeyCredential) && window.isSecureContext && !isIP;
  }

  async function create(options) {
    const credential = await navigator.credentials.create({
      publicKey: {
        ...options,
        challenge: toBytes(options.challenge),
        user: { ...options.user, id: toBytes(options.user.id) },
        excludeCredentials: decodeList(options.excludeCredentials),
      },
    });
    const { response } = credential;
    return {
      id: credential.id,
      rawId: toText(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: toText(response.clientDataJSON),
        attestationObject: toText(response.attestationObject),
        transports: response.getTransports ? response.getTransports() : [],
      },
    };
  }

  async function get(options) {
    const credential = await navigator.credentials.get({
      publicKey: {
        ...options,
        challenge: toBytes(options.challenge),
        allowCredentials: decodeList(options.allowCredentials),
      },
    });
    const { response } = credential;
    return {
      id: credential.id,
      rawId: toText(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: toText(response.clientDataJSON),
        authenticatorData: toText(response.authenticatorData),
        signature: toText(response.signature),
        userHandle: response.userHandle ? toText(response.userHandle) : '',
      },
    };
  }

  // The browser reports a cancelled prompt as an error, which needs no message.
  const cancelled = (error) => error && error.name === 'NotAllowedError';

  async function signIn(button) {
    button.disabled = true;
    try {
      const { data } = await request(button.dataset.passkey);
      const credential = await get(data.options);
      const form = h('form', { method: 'post', action: `${button.dataset.passkey}${location.search}`, hidden: true }, [
        h('input', { type: 'hidden', name: '_form_token', value: button.dataset.formToken }),
        h('input', { type: 'hidden', name: 'passkey_token', value: data.token }),
        h('input', { type: 'hidden', name: 'credential', value: JSON.stringify(credential) }),
      ]);
      document.body.append(form);
      form.submit();
    } catch (error) {
      button.disabled = false;
      if (!cancelled(error)) toast('error', errorText(error, 'passkey.err_failed'));
    }
  }

  window.WCPasskey = { supported, create, cancelled };

  WC.ready.then(() => {
    const button = $('[data-passkey]');
    if (!button) return;
    // A refused sign in answers on the address that was posted to, where a reload would not
    // show this page again.
    if (location.pathname === button.dataset.passkey) {
      history.replaceState(null, '', `${location.pathname.replace(/\/passkey$/, '')}${location.search}`);
    }
    if (supported()) {
      button.hidden = false;
      button.addEventListener('click', () => signIn(button));
    } else if ('passkeyOnly' in button.dataset) {
      // Without a code to enter, say why there is nothing to do here.
      $('#passkey-unavailable').hidden = false;
    }
  });
})();
