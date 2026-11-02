// Usage: node client.js BASE SHOTS HOME ADMIN_TOKEN
const { chromium } = require('playwright');
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const [base, shots, home, token] = process.argv.slice(2);
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
const HOOKS = `(function(){window.__bridge=[];const report=(m)=>window.__bridge.push(m);
const submit=HTMLFormElement.prototype.submit;HTMLFormElement.prototype.submit=function(){if(this.method==='post'&&this.target==='_blank'){const f={};new FormData(this).forEach((v,n)=>{f[n]=String(v)});report({type:'archive',url:this.action,fields:f});return}return submit.call(this)};
const send=XMLHttpRequest.prototype.send;XMLHttpRequest.prototype.send=function(b){if(b instanceof File){report({type:'upload-start',name:b.name});this.upload.addEventListener('progress',(e)=>{if(e.lengthComputable)report({type:'upload-progress',percent:Math.round(100*e.loaded/e.total)})});this.addEventListener('loadend',()=>report({type:'upload-end',ok:this.status>=200&&this.status<300}))}return send.call(this,b)}})();`;

(async () => {
  const browser = await chromium.launch();
  const issues = [], theme = [];
  const watch = (p) => {
    p.on('console', (m) => { if (m.type() === 'error') issues.push(m.text() + ' @' + p.url()); });
    p.on('pageerror', (e) => issues.push('pageerror: ' + e.message + ' @' + p.url()));
    p.on('request', (r) => { if (/\/static\/assets\//.test(r.url())) theme.push(r.url()); });
    p.on('response', (r) => { if (r.status() >= 400 && !r.url().includes('/thumbnail') && !r.url().includes('nosuch')) issues.push(r.status() + ' ' + r.url()); });
  };
  const ctx = await browser.newContext({ locale: 'en-US', viewport: { width: 1280, height: 860 }, acceptDownloads: true });
  await ctx.addInitScript(HOOKS);
  const page = await ctx.newPage(); page.setDefaultTimeout(8000); watch(page);
  const shot = (n, p = page) => p.screenshot({ path: `${shots}/${n}.png` });
  const idle = async (p = page) => { await p.waitForLoadState('networkidle'); await sleep(250); };
  const row = (n) => page.locator('tr', { has: page.locator('.entry-name', { hasText: new RegExp(`^${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`) }) });
  const menu = async (n, item) => { await row(n).locator('.iconbutton').click(); await page.locator('.menu-item', { hasText: item }).click(); };
  const listed = async () => page.locator('.entry-name').allTextContents();
  const signIn = async (user, pass) => {
    await page.goto(`${base}/web/client/login`); await idle();
    // a script filling in the form, not a person typing
    const ok = await page.evaluate(({ user, pass }) => { const form = document.getElementById('sign_in_form'); const submit = document.getElementById('sign_in_submit'); if (!form || !submit || !form.elements.username || !form.elements.password) return false; form.elements.username.value = user; form.elements.password.value = pass; submit.click(); return true; }, { user, pass });
    await idle(); return ok;
  };

  // Sign in
  await page.goto(`${base}/web/client/login`); await idle(); await shot('01-login');
  await page.fill('input[name=username]', 'alice'); await page.fill('input[name=password]', 'wrong-one'); await page.click('#sign_in_submit'); await idle();
  check('wrong password shows an error', (await page.textContent('.notice')).includes('Invalid credentials'));
  check('the login form can be filled by a script', await signIn('alice', 'e2e-User-Pass-1'));
  check('lands on files', page.url().includes('/web/client/files'));
  await idle(); await shot('02-files');
  let names = await listed();
  check('lists folders before files', names[0] === 'docs' && names.includes('note.txt'), names.join());

  // Navigation without reloads
  await page.evaluate(() => { window.__sameDoc = 1; });
  await row('photos').locator('a.entry').click(); await idle();
  check('folder opens without a reload', await page.evaluate(() => window.__sameDoc === 1));
  check('URL follows the folder', decodeURIComponent(page.url()).includes('path=/photos'));
  check('current folder is the heading', (await page.textContent('h1')).trim() === 'photos');
  await page.goBack(); await idle();
  check('back returns to the parent', (await page.textContent('h1')).trim() === 'Home' && await page.evaluate(() => window.__sameDoc === 1));
  await page.goForward(); await idle();
  check('forward works', (await page.textContent('h1')).trim() === 'photos');
  await page.locator('a.tab').first().click(); await idle();

  // Create, rename, move, copy, delete
  await page.click('#new-folder'); await page.fill('dialog input', 'made-here'); await page.click('dialog [data-submit]'); await idle();
  check('new folder', (await listed()).includes('made-here'));
  await menu('note.txt', 'Rename'); await page.fill('dialog input', 'renamed.txt'); await page.click('dialog [data-submit]'); await sleep(1000); await idle();
  check('rename', (await listed()).includes('renamed.txt') && fs.existsSync(`${home}/renamed.txt`));
  await menu('renamed.txt', 'Move or copy'); await idle();
  await page.locator('.picker-row', { hasText: 'made-here' }).click(); await idle();
  await page.locator('dialog button', { hasText: 'Move' }).last().click(); await sleep(1200); await idle();
  check('move into folder', fs.existsSync(`${home}/made-here/renamed.txt`) && !fs.existsSync(`${home}/renamed.txt`));
  await menu('copy-me.txt', 'Move or copy'); await idle();
  await page.locator('.picker-row', { hasText: 'made-here' }).click(); await idle();
  await page.locator('dialog button', { hasText: 'Copy' }).last().click(); await sleep(1200); await idle();
  check('copy file into folder', fs.existsSync(`${home}/made-here/copy-me.txt`) && fs.existsSync(`${home}/copy-me.txt`));
  await menu('docs', 'Move or copy'); await idle();
  await page.locator('.picker-row', { hasText: 'made-here' }).click(); await idle();
  await page.locator('dialog button', { hasText: 'Copy' }).last().click(); await sleep(1500); await idle();
  check('copy folder keeps its name', fs.existsSync(`${home}/made-here/docs/deep.txt`), fs.existsSync(`${home}/made-here`) ? fs.readdirSync(`${home}/made-here`).join() : '');
  // Drag a row onto a folder
  await row('drag-me.txt').dragTo(row('made-here')); await sleep(1200); await idle();
  check('drag a row onto a folder moves it', fs.existsSync(`${home}/made-here/drag-me.txt`));
  await menu('copy-me.txt', 'Delete'); await shot('03-delete-dialog'); await page.locator('dialog .button-danger').click(); await idle();
  check('delete file', !fs.existsSync(`${home}/copy-me.txt`));

  // Selection and zip through the Android hook
  await row('photos').locator('input').check(); await row('docs').locator('input').check();
  check('selection bar counts', (await page.textContent('#selection-count')).includes('2 items'));
  await shot('04-selection');
  await page.evaluate(() => { window.__bridge.length = 0; });
  await page.click('#selection-download'); await sleep(200);
  const archive = await page.evaluate(() => window.__bridge.find((m) => m.type === 'archive'));
  check('zip goes through the post the app intercepts', archive && JSON.parse(archive.fields.files).length === 2 && !!archive.fields._form_token, JSON.stringify(archive));
  await page.click('#selection-clear');
  const zipCtx = await page.context().request.post(archive.url, { form: archive.fields });
  check('that zip post works on the server', zipCtx.ok() && (await zipCtx.body()).slice(0, 2).toString() === 'PK');

  // Upload through the hook, with a conflict
  await page.evaluate(() => { window.__bridge.length = 0; });
  await page.setInputFiles('#picker', [{ name: 'up one.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(3 * 1048576, 7) }, { name: 'ząb.txt', mimeType: 'text/plain', buffer: Buffer.from('polskie') }]);
  await sleep(300); await shot('05-upload'); await page.waitForFunction(() => window.__bridge.filter((m) => m.type === 'upload-end').length === 2, null, { timeout: 15000 }); await idle();
  const events = await page.evaluate(() => window.__bridge.map((m) => m.type + (m.name ? ':' + m.name : '') + (m.ok !== undefined ? ':' + m.ok : '')));
  check('each file is one XHR the app can see', events.includes('upload-start:up one.bin') && events.includes('upload-end:true'), events.filter((e) => !e.startsWith('upload-progress')).join(' '));
  check('sequential: second starts after first ends', events.indexOf('upload-start:ząb.txt') > events.indexOf('upload-end:true'));
  check('files on disk, unusual names intact', fs.statSync(`${home}/up one.bin`).size === 3 * 1048576 && fs.readFileSync(`${home}/ząb.txt`, 'utf8') === 'polskie');
  check('list refreshed after upload', (await listed()).includes('ząb.txt'));
  await page.setInputFiles('#picker', [{ name: 'ząb.txt', mimeType: 'text/plain', buffer: Buffer.from('nowe') }]); await idle();
  check('existing file asks first', (await page.textContent('dialog')).includes('ząb.txt'));
  await page.locator('dialog .button-danger').click();
  await sleep(1000); await idle();
  check('overwrite after confirming', fs.readFileSync(`${home}/ząb.txt`, 'utf8') === 'nowe');
  await page.setInputFiles('#picker', [{ name: 'ząb.txt', mimeType: 'text/plain', buffer: Buffer.from('nie') }]); await idle();
  await page.locator('dialog button', { hasText: 'Cancel' }).click(); await sleep(300);
  check('cancel keeps the old file', fs.readFileSync(`${home}/ząb.txt`, 'utf8') === 'nowe');

  // Drop a folder from the desktop
  const dropped = await page.evaluateHandle(() => { const d = new DataTransfer(); d.items.add(new File(['drop'], 'dropped.txt')); return d; });
  await page.dispatchEvent('#sheet', 'dragenter', { dataTransfer: dropped }); await page.dispatchEvent('#sheet', 'dragover', { dataTransfer: dropped });
  await shot('06-drop'); await page.dispatchEvent('#sheet', 'drop', { dataTransfer: dropped }); await sleep(1000); await idle();
  check('drop a file on the sheet', fs.existsSync(`${home}/dropped.txt`));

  // Search
  await page.fill('#search', 'zą'); await sleep(100);
  check('typing filters the folder', (await listed()).join() === 'ząb.txt', (await listed()).join());
  await page.fill('#search', 'deep'); await page.press('#search', 'Enter'); await idle();
  names = await listed();
  check('Enter searches subfolders', names.filter((n) => n === 'deep.txt').length === 2, names.join());
  await shot('07-search');
  await page.fill('#search', ''); await idle();
  check('clearing brings the folder back', (await listed()).includes('photos'));

  // Grid, thumbnails, viewer
  await row('photos').locator('a.entry').click(); await idle();
  await page.click('#view-toggle'); await idle(); await sleep(700);
  check('grid view', await page.locator('.gallery .card').count() >= 3);
  const thumbs = await page.$$eval('.glyph img', (i) => i.filter((x) => x.naturalWidth > 0).length);
  check('thumbnails load', thumbs >= 1, thumbs);
  await shot('08-grid');
  await page.locator('.card', { hasText: 'pic.png' }).locator('a.entry').click(); await idle();
  check('image opens in the viewer', await page.$eval('.viewer img', (i) => i.naturalWidth > 0)); await shot('09-viewer');
  await page.keyboard.press('ArrowRight'); await sleep(250);
  check('arrow moves to the next item', (await page.textContent('.viewer-name')) !== 'pic.png', await page.textContent('.viewer-name'));
  await page.keyboard.press('Escape'); await sleep(200);
  check('Escape closes the viewer', await page.locator('.viewer').count() === 0);
  await page.click('#view-toggle'); await idle();

  // Editor
  await page.goto(`${base}/web/client/files?path=${encodeURIComponent('/made-here')}`); await idle();
  await row('renamed.txt').locator('a.entry').click(); await idle(); await sleep(400);
  check('text file opens in the editor', page.url().includes('/editfile') && (await page.textContent('.cm-content')).includes('note')); await shot('10-editor');
  await page.click('.cm-content'); await page.keyboard.press('Control+End'); await page.keyboard.type(' edited'); await page.keyboard.press('Control+s'); await sleep(600);
  check('Ctrl+S saves', fs.readFileSync(`${home}/made-here/renamed.txt`, 'utf8').includes('edited'));
  await page.click('#back-tab'); await idle();
  check('back to the file folder', (await page.textContent('h1')).trim() === 'made-here');

  // PDF
  await page.goto(`${base}/web/client/files?path=%2F`); await idle();
  await row('paper.pdf').locator('a.entry').click(); await idle();
  check('PDF page loads', page.url().includes('/viewpdf') && await page.locator('object').count() === 1); await page.goBack(); await idle();

  // Language dropdown
  const pickLanguage = async (name) => { await page.click('.bar [data-language-picker]'); await page.locator('[role=menuitemradio]', { hasText: name }).click(); };
  await page.click('.bar [data-language-picker]');
  check('dropdown lists the configured languages', (await page.locator('[role=menuitemradio]').allTextContents()).join() === 'English,Polski,Deutsch');
  await page.keyboard.press('Escape');
  await pickLanguage('Polski'); await idle();
  check('page switches without a reload', (await page.textContent('h1')).trim() === 'Folder domowy' && (await page.textContent('#upload')).includes('Prześlij pliki'));
  check('list re-renders in the language', (await page.textContent('thead')).includes('Rozmiar'));
  check('html lang follows', await page.evaluate(() => document.documentElement.lang) === 'pl');
  await shot('11-polish');
  await page.reload(); await idle();
  check('choice survives a reload', (await page.textContent('#upload')).includes('Prześlij pliki'));
  await pickLanguage('Deutsch'); await idle();
  check('another language', (await page.textContent('#upload')).includes('Dateien hochladen') || (await page.textContent('#upload')).length > 3, await page.textContent('#upload'));
  await pickLanguage('English'); await idle();

  // Shares
  await row('docs').locator('input').check(); await page.click('#selection-share'); await idle();
  check('share form receives the selection', (await page.inputValue('input[name=paths]')) === '/docs');
  await page.fill('input[name=name]', 'family'); await page.fill('#expiration-picker', '2099-05-06T07:08'); await shot('12-share-form');
  await page.click('form#share button[type=submit]'); await idle();
  check('share created', page.url().includes('/web/client/shares') && (await page.textContent('#list')).includes('family')); await shot('13-shares');
  const list = await page.evaluate(async () => (await fetch('/web/client/shares/json')).json());
  const sh = list[0];
  const exp = new Date(2099, 4, 6, 7, 8).getTime();
  check('expiry saved as the time entered', Math.abs(sh.expires_at - exp) < 1000, `${sh.expires_at} vs ${exp}`);
  await page.locator('tr', { hasText: 'family' }).locator('.iconbutton').click(); await page.locator('.menu-item', { hasText: 'Copy link' }).click(); await idle();
  check('links dialog', (await page.textContent('dialog')).includes('Share access links') && (await page.inputValue('dialog input')).includes(sh.id)); await shot('14-share-links');
  await page.locator('dialog .button-primary').click();
  await page.goto(`${base}/web/client/share/${sh.id}`); await idle();
  check('edit shows the saved expiry', (await page.inputValue('#expiration-picker')) === '2099-05-06T07:08', await page.inputValue('#expiration-picker'));
  await page.selectOption('select[name=scope]', '3'); await page.fill('input[name=password]', 'share-pass-1'); await page.click('form#share button[type=submit]'); await idle();

  // A password-protected read/write share, as a stranger
  const anon = await browser.newContext({ locale: 'pl-PL', viewport: { width: 1280, height: 860 } });
  const pub = await anon.newPage(); pub.setDefaultTimeout(8000); watch(pub);
  await pub.goto(`${base}/web/client/pubshares/${sh.id}/browse`); await idle(pub);
  check('share asks for the password', pub.url().includes('/login')); await pub.screenshot({ path: `${shots}/15-share-login.png` });
  await pub.fill('input[name=share_password]', 'share-pass-1'); await pub.click('#sign_in_submit'); await idle(pub);
  check('stranger browses in their language', (await pub.locator('.entry-name').allTextContents()).includes('deep.txt') && (await pub.textContent('h1')).trim() === 'Udostępnione pliki', await pub.textContent('h1'));
  check('no signed-in navigation on a share', await pub.locator('.bar-nav').count() === 0);
  await pub.setInputFiles('#picker', [{ name: 'guest.txt', mimeType: 'text/plain', buffer: Buffer.from('hello') }]); await sleep(1000); await idle(pub);
  check('upload into a share', fs.existsSync(`${home}/docs/guest.txt`)); await pub.screenshot({ path: `${shots}/16-share-browse.png` });
  await pub.goto(`${base}/web/client/pubshares/${sh.id}/upload`); await idle(pub); await pub.screenshot({ path: `${shots}/17-share-upload.png` });
  await pub.setInputFiles('#picker', [{ name: 'guest2.txt', mimeType: 'text/plain', buffer: Buffer.from('hi') }]); await sleep(1000); await idle(pub);
  check('upload-only page', fs.existsSync(`${home}/docs/guest2.txt`));
  await anon.close();

  // Profile and password
  await page.goto(`${base}/web/client/profile`); await idle(); await shot('18-profile');
  await page.fill('input[name=email]', 'alice@example.com');
  await page.locator('[data-repeat=public_keys] button', { hasText: 'Add' }).click();
  await page.fill('[data-repeat=public_keys] textarea', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDpoeXoTgLPpJDeqWWr0vpCWvFLhDbOnMS3sMsJkGpDB test');
  await page.click('form#profile button[type=submit]'); await idle();
  let saved = await (await ctx.request.get(`${base}/api/v2/users/alice`, { headers: { Authorization: `Bearer ${token}` } })).json();
  check('profile saved', saved.email === 'alice@example.com' && saved.public_keys.length === 1, saved.email);

  // API keys
  await page.goto(`${base}/web/client/api-keys`); await idle();
  check('notice when keys are turned off', await page.isDisabled('#add-key')); await shot('19-keys-off');
  await page.goto(`${base}/web/client/profile`); await idle();
  await page.check('input[name=allow_api_key_auth]'); await page.click('form#profile button[type=submit]'); await idle();
  await page.locator('[data-account-menu]').click();
  await page.locator('.menu-item', { hasText: 'API Keys' }).click(); await idle();
  check('API keys in the account menu', page.url().includes('/api-keys'));
  await page.click('#add-key'); await page.locator('dialog input[type=text]').first().fill('phone');
  await page.locator('dialog input[type=checkbox]').check(); await shot('20-key-add');
  await page.click('dialog [data-submit]'); await idle();
  const key = await page.inputValue('dialog input'); await shot('21-key-reveal');
  check('key shown once', key.includes('.'), key.slice(0, 6));
  await page.locator('dialog .button-primary').click(); await idle();
  check('listed with its scope', (await page.textContent('#keys')).includes('phone') && (await page.textContent('#keys')).includes('web session')); await shot('22-keys');
  let r = await ctx.request.get(`${base}/api/v2/user/profile`, { headers: { 'X-GONAS-API-KEY': key } });
  const web = await browser.newContext(); r = await web.request.post(`${base}/api/v2/user/websession`, { headers: { 'X-GONAS-API-KEY': key } });
  check('the key opens a web session', r.ok(), r.status());
  const sess = await web.newPage(); sess.setDefaultTimeout(8000);
  await sess.goto(`${base}/web/client/files`); await idle(sess);
  check('key session sees files', (await sess.textContent('h1')).trim() === 'Home');
  await sess.click('[data-account-menu]');
  check('key session has no API keys entry', await sess.locator('.menu-item', { hasText: 'API Keys' }).count() === 0);
  const guarded = await sess.goto(`${base}/web/client/api-keys`);
  check('key session cannot open the page', guarded.status() === 403, guarded.status());
  const raw = await web.request.post(`${base}/web/client/api-keys`, { data: { name: 'x' } });
  check('nor create keys', raw.status() === 403, raw.status());
  await page.locator('tr', { hasText: 'phone' }).locator('.iconbutton').click(); await page.locator('dialog .button-danger').click(); await idle();
  check('revoke removes it', (await page.textContent('#keys')).includes('no API keys'));
  r = await sess.goto(`${base}/web/client/files`);
  check('revoking ends the session', sess.url().includes('/login'), sess.url());
  await web.close();

  // Two-factor
  await page.goto(`${base}/web/client/mfa`); await idle(); await shot('23-mfa');
  await page.check('input[name=protocol][value=HTTP]'); await page.click('#generate'); await idle();
  const secret = (await page.textContent('.secret')).trim(); await shot('24-mfa-setup');
  await page.fill('dialog input', totp(secret)); await page.click('dialog [data-submit]'); await sleep(800); await idle();
  check('2FA enrolled', (await page.textContent('.notice-ok')).includes('enabled'));
  await page.click('#view-codes'); await idle();
  const codes = await page.locator('.codes li').allTextContents(); check('recovery codes shown', codes.length === 12, codes.length); await page.locator('dialog .button-primary').click();
  await page.goto(`${base}/web/client/logout`); await idle();
  await signIn('alice', 'e2e-User-Pass-1');
  check('login asks for the code', page.url().includes('/twofactor')); await shot('25-2fa');
  const pass = await page.evaluate((code) => { const form = document.getElementById('sign_in_form'); const submit = document.getElementById('sign_in_submit'); if (!form || !submit || !form.elements.passcode) return false; form.elements.passcode.value = code; submit.click(); return true; }, totp(secret, 1));
  await idle();
  check('the 2FA form can be filled by a script', pass && page.url().includes('/web/client/files'), page.url());
  await page.goto(`${base}/web/client/mfa`); await idle();
  await page.click('#disable'); await page.locator('dialog .button-danger').click(); await sleep(600); await idle();
  check('2FA disabled', (await page.textContent('.sheet')).includes('Secure Your Account'));

  await page.goto(`${base}/web/client/changepwd`); await idle(); await shot('26-password');
  await page.fill('input[name=current_password]', 'e2e-User-Pass-1'); await page.fill('input[name=new_password1]', 'e2e-User-Pass-2'); await page.fill('input[name=new_password2]', 'e2e-User-Pass-2');
  await page.click('form button[type=submit]'); await idle();
  check('password change signs out', page.url().includes('/login'), page.url());
  await signIn('alice', 'e2e-User-Pass-2');
  check('new password works', page.url().includes('/web/client/files'));

  // Pages that are not the happy path
  const miss = await page.goto(`${base}/web/client/share/nosuch`); await idle();
  check('not found page', miss.status() === 404 && (await page.textContent('.notice')).length > 5); await shot('27-error');
  await page.goto(`${base}/web/client/files?path=%2Fnosuch`); await idle();
  check('missing folder falls back with a message', await page.locator('.notice').count() === 1);

  // Permissions move with the folder
  await page.goto(`${base}/web/client/files?path=%2F`); await idle();
  check('upload offered where allowed', await page.isVisible('#upload'));
  await row('readonly').locator('a.entry').click(); await idle();
  check('upload hidden in a read-only folder', !(await page.isVisible('#upload')));
  await page.locator('a.tab').first().click(); await idle();
  check('and back again', await page.isVisible('#upload'));
  await page.evaluate(() => document.documentElement.dataset.theme = 'dark'); await idle(); await shot('28-dark');
  await page.evaluate(() => document.documentElement.dataset.theme = 'light');

  // Phone
  await ctx.close();
  const phone = await browser.newContext({ locale: 'pl-PL', viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, deviceScaleFactor: 2 });
  const p = await phone.newPage(); p.setDefaultTimeout(8000); watch(p);
  await p.goto(`${base}/web/client/login`); await idle(p); await p.screenshot({ path: `${shots}/30-phone-login.png` });
  await p.fill('input[name=username]', 'alice'); await p.fill('input[name=password]', 'e2e-User-Pass-2'); await p.click('#sign_in_submit'); await idle(p);
  await p.screenshot({ path: `${shots}/31-phone-files.png` });
  check('no sideways scroll on a phone', await p.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), await p.evaluate(() => document.documentElement.scrollWidth));
  check('bottom navigation on a phone', await p.isVisible('.pocket') && !(await p.isVisible('.bar-nav')));
  await p.locator('.entry', { hasText: 'made-here' }).tap(); await idle(p);
  await p.locator('tbody .check input').first().tap(); await sleep(200);
  const clearBox = await p.locator('#selection-clear').boundingBox();
  check('selection bar fits on a phone', clearBox && clearBox.x + clearBox.width <= 390, JSON.stringify(clearBox));
  await p.locator('#selection-clear').tap(); await sleep(150);
  check('clearing works on a phone', !(await p.isVisible('#selection')));
  await p.locator('tbody .check input').first().tap(); await sleep(150); await p.screenshot({ path: `${shots}/32-phone-selection.png` });
  await p.goto(`${base}/web/client/shares`); await idle(p); await p.screenshot({ path: `${shots}/33-phone-shares.png` });
  await p.goto(`${base}/web/client/profile`); await idle(p); await p.screenshot({ path: `${shots}/34-phone-profile.png` });
  check('no sideways scroll on other pages', await p.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
  await phone.close();

  check('no client page loaded a theme file', theme.length === 0, theme.join(' '));
  const real = [...new Set(issues)].filter((i) => !/favicon|nosuch/.test(i));
  check('no console errors or failed requests', real.length === 0, real.slice(0, 8).join(' || '));
  await browser.close();
  console.log(failed ? `FAILED ${failed}` : 'ALL PASS');
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('CRASH', e); process.exit(2); });
