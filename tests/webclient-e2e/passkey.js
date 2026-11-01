// Usage: node passkey.js BASE SHOTS TOKEN on|off
// Signs in with real WebAuthn, through Chromium's virtual authenticator. "on" and "off" are the
// values of httpd.passkeys.skip_two_factor on the server.
const { chromium } = require('playwright');
const crypto = require('crypto');
const [base, shots, token, mode] = process.argv.slice(2);
const skip = mode === 'on';
let failed = 0;
const check = (n, ok, x = '') => { if (!ok) failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${x !== '' ? '  -> ' + String(x).slice(0, 300) : ''}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function totp(secret, step = 0) {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const c of secret.replace(/=+$/, '')) bits += a.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + step));
  const h = crypto.createHmac('sha1', key).update(buf).digest(); const o = h[19] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}
const api = async (path, method = 'GET', body) => {
  const r = await fetch(`${base}/api/v2${path}`, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text(); try { return { status: r.status, data: JSON.parse(text) }; } catch { return { status: r.status, data: text }; }
};
const addUser = (name, filters = {}) => api('/users', 'POST', { username: name, password: 'e2e-User-Pass-1', status: 1, home_dir: `/tmp/gonas-e2e-${name}`, permissions: { '/': ['*'] }, filters });

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ locale: 'en-US', viewport: { width: 1280, height: 860 } });
  const page = await ctx.newPage(); page.setDefaultTimeout(8000);
  const issues = [];
  page.on('console', (m) => { if (m.type() === 'error' && !/40[013]|Failed to load resource/.test(m.text())) issues.push(m.text() + ' @' + page.url()); });
  page.on('pageerror', (e) => issues.push('pageerror: ' + e.message + ' @' + page.url()));
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const authenticator = async () => (await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })).authenticatorId;
  let device = await authenticator();
  const idle = async () => { await page.waitForLoadState('networkidle'); await sleep(200); };
  const shot = (n) => page.screenshot({ path: `${shots}/${n}.png`, fullPage: true });
  const path = () => new URL(page.url()).pathname;
  const notice = async () => { const n = page.locator('.notice:visible'); return (await n.count()) ? (await n.first().textContent()).trim() : ''; };
  const signIn = async (ui, user, pass) => { await page.goto(`${base}/web/${ui}/login`); await idle(); await page.fill('input[name=username]', user); await page.fill('input[name=password]', pass); await page.click('#sign_in_submit'); await idle(); };
  const passkeyButton = () => page.locator('[data-passkey]');
  const usePasskey = async () => { await passkeyButton().click(); await sleep(400); await idle(); };
  const signOut = async (ui) => { await page.goto(`${base}/web/${ui}/logout`); await idle(); };
  const addPasskey = async (ui, name) => {
    await page.goto(`${base}/web/${ui}/mfa`); await idle();
    await page.click('#add-passkey'); await page.fill('dialog input', name); await page.click('dialog [data-submit]');
    await sleep(800); await idle();
  };
  const enableTOTP = async (ui) => {
    await page.goto(`${base}/web/${ui}/mfa`); await idle();
    const http = page.locator('input[name=protocol][value=HTTP]'); if (await http.count()) await http.check();
    await page.click('#generate'); await idle();
    const secret = (await page.textContent('.secret')).trim();
    await page.fill('dialog input', totp(secret)); await page.click('dialog [data-submit]'); await sleep(800); await idle();
    return secret;
  };

  // Where a passkey cannot work, the page says why
  await page.goto(`${base.replace('localhost', '127.0.0.1')}/web/client/login`); await idle();
  check('no passkey button on an IP address', !(await passkeyButton().isVisible()));

  await addUser('alice');
  await signIn('client', 'alice', 'e2e-User-Pass-1');
  check('password sign in', path() === '/web/client/files', page.url());
  await addPasskey('client', 'Laptop');
  check('passkey added', (await page.locator('.passkey-name').allTextContents()).includes('Laptop'));
  await shot(`passkey-${mode}-mfa`);
  await signOut('client');
  await page.goto(`${base}/web/client/login`); await idle(); await shot(`passkey-${mode}-login`);
  check('passkey button on the login page', await passkeyButton().isVisible());
  await usePasskey();
  check('signs in with a passkey and no password', path() === '/web/client/files', page.url());
  await signOut('client');

  // A captured sign in must not work twice
  await page.goto(`${base}/web/client/login`); await idle();
  let captured = '';
  const capture = (r) => { if (r.method() === 'POST' && r.url().includes('/login/passkey')) captured = r.postData(); };
  page.on('request', capture);
  await usePasskey(); page.off('request', capture);
  check('passkey post seen', captured.includes('passkey_token'));
  await signOut('client');
  await page.goto(`${base}/web/client/login`); await idle();
  const fresh = await page.inputValue('input[name=_form_token]');
  const replay = new URLSearchParams(captured); replay.set('_form_token', fresh);
  const again = await page.evaluate(async (body) => { const r = await fetch('/web/client/login/passkey', { method: 'POST', body: new URLSearchParams(body), redirect: 'manual' }); return r.type; }, replay.toString());
  check('replaying a sign in is refused', again !== 'opaqueredirect', again);

  // Passkey with TOTP
  await signIn('client', 'alice', 'e2e-User-Pass-1');
  const secret = await enableTOTP('client');
  await signOut('client');
  await page.goto(`${base}/web/client/login`); await idle();
  await usePasskey();
  if (skip) {
    check('with the option on, a passkey skips the code', path() === '/web/client/files', page.url());
    await signOut('client');
    await signIn('client', 'alice', 'e2e-User-Pass-1');
    check('a password still asks for the second factor', path() === '/web/client/twofactor', page.url());
    await shot(`passkey-${mode}-twofactor`);
    check('the code and a passkey are both offered', (await page.locator('input[name=passcode]').count()) === 1 && (await passkeyButton().isVisible()));
    await usePasskey();
    check('a passkey works in place of the code', path() === '/web/client/files', page.url());
    await signOut('client');
    await signIn('client', 'alice', 'e2e-User-Pass-1');
    // The next period's code: the server refuses one it has already seen.
    await page.fill('input[name=passcode]', totp(secret, 1)); await page.click('#sign_in_submit'); await idle();
    check('the code keeps working', path() === '/web/client/files', page.url());
    await signOut('client');
  } else {
    check('with the option off, a passkey still asks for the code', path() === '/web/client/twofactor', page.url());
    check('and offers no passkey for the second step', (await passkeyButton().count()) === 0);
    await page.goto(`${base}/web/client/files`); await idle();
    check('nothing opens before the code', path() !== '/web/client/files', page.url());
    await page.goto(`${base}/web/client/login`); await idle(); await usePasskey();
    await page.fill('input[name=passcode]', totp(secret, 1)); await page.click('#sign_in_submit'); await idle();
    check('passkey and code sign in', path() === '/web/client/files', page.url());
    await signOut('client');
    await signIn('client', 'alice', 'e2e-User-Pass-1');
    check('a password asks for the code', path() === '/web/client/twofactor', page.url());
    check('and offers no passkey', (await passkeyButton().count()) === 0);
  }
  await ctx.clearCookies();

  // An account that must use a second factor
  await addUser('bob', { two_factor_protocols: ['HTTP'] });
  await signIn('client', 'bob', 'e2e-User-Pass-1');
  check('a required account goes to the 2FA page', path() === '/web/client/mfa', page.url());
  await addPasskey('client', 'Phone');
  if (skip) {
    check('saving the passkey ends the session', path().endsWith('/login'), page.url());
    await signIn('client', 'bob', 'e2e-User-Pass-1');
    check('a password alone is not enough', path() === '/web/client/twofactor', page.url());
    check('with no TOTP there is no code field', (await page.locator('input[name=passcode]').count()) === 0);
    await page.goto(`${base}/web/client/files`); await idle();
    check('files stay closed', path() !== '/web/client/files', page.url());
    await page.goto(`${base}/web/client/twofactor`); await idle();
    await usePasskey();
    check('the passkey completes the sign in', path() === '/web/client/files', page.url());
    await page.goto(`${base}/web/client/mfa`); await idle();
    await page.click('#view-codes'); await idle();
    const codes = await page.locator('.codes li').allTextContents();
    check('recovery codes exist for a passkey-only account', codes.length === 12, codes.length);
    await page.locator('dialog .button-primary').click();
    await page.click('[data-passkey-delete]'); await page.locator('dialog .button-danger').click(); await sleep(600);
    check('the last required passkey cannot be removed', /required/i.test(await page.textContent('#toasts')), await page.textContent('#toasts'));
    await signOut('client');
    await signIn('client', 'bob', 'e2e-User-Pass-1');
    await page.goto(`${base}/web/client/twofactor-recovery`); await idle();
    await page.fill('input[name=recovery_code]', codes[0].trim()); await page.click('#sign_in_submit'); await idle();
    check('a recovery code replaces a lost passkey', path() === '/web/client/files', page.url());
    await signOut('client');
    // Everyday admin work must not touch them
    const before = (await api('/users/bob')).data;
    check('passkeys are stored', (before.filters.passkeys || []).length === 1);
    const put = await api('/users/bob', 'PUT', { ...before, description: 'edited', filters: { ...before.filters, passkeys: [] } });
    check('updating a user over REST works', put.status === 200, JSON.stringify(put.data));
    check('and keeps the passkeys', ((await api('/users/bob')).data.filters.passkeys || []).length === 1);
    const off = await api('/users/bob/2fa/disable', 'PUT');
    check('an admin can reset a lost passkey', off.status === 200, JSON.stringify(off.data));
    check('resetting removes it', ((await api('/users/bob')).data.filters.passkeys || []).length === 0);
  } else {
    check('with the option off, a passkey does not meet the requirement', path() === '/web/client/mfa', page.url());
    await signOut('client');
    await signIn('client', 'bob', 'e2e-User-Pass-1');
    check('so the account still has to set up TOTP', path() === '/web/client/mfa', page.url());
    await page.goto(`${base}/web/client/files`); await idle();
    check('and files stay closed', path() === '/web/client/mfa', page.url());
    await signOut('client');
  }

  // Admins
  await ctx.clearCookies();
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: device }); device = await authenticator();
  await signIn('admin', 'admin', 'e2e-Password-1');
  await addPasskey('admin', 'Admin key');
  check('admin passkey added', (await page.locator('.passkey-name').allTextContents()).includes('Admin key'));
  await signOut('admin');
  await page.goto(`${base}/web/admin/login`); await idle(); await usePasskey();
  check('admin signs in with a passkey', path() === '/web/admin/users', page.url());
  await page.goto(`${base}/web/admin/users`); await idle(); await shot(`passkey-${mode}-admin`);
  await page.goto(`${base}/web/admin/mfa`); await idle();
  await page.click('[data-passkey-delete]'); await page.locator('dialog .button-danger').click(); await sleep(600); await idle();
  check('a passkey can be removed', (await page.locator('.passkey-name').count()) === 0);
  await signOut('admin');
  await page.goto(`${base}/web/admin/login`); await idle();
  await passkeyButton().click(); await sleep(900); await idle();
  check('a removed passkey no longer signs in', path() === '/web/admin/login', page.url());
  check('and says so', /invalid/i.test(await notice()), await notice());

  check('no script errors', issues.length === 0, issues.slice(0, 6).join(' | '));
  await browser.close();
  console.log(failed ? `\n${failed} FAILED` : '\nALL PASSED');
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
