// Usage: node admin.js BASE SHOTS HOME
// Runs the WebAdmin from an empty database: first admin, every page, then each kind of object.
const { chromium } = require('playwright');
const crypto = require('crypto');
const [base, shots, home] = process.argv.slice(2);
const admin = `${base}/web/admin`;
let failed = 0;
const check = (n, ok, x = '') => { if (!ok) failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${x !== '' ? '  -> ' + String(x).slice(0, 300) : ''}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function totp(secret) {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '';
  for (const c of secret.replace(/=+$/, '')) bits += a.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const buf = Buffer.alloc(8); buf.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = crypto.createHmac('sha1', key).update(buf).digest(); const o = h[19] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}

(async () => {
  const browser = await chromium.launch({ args: process.env.CHROME_ARGS ? process.env.CHROME_ARGS.split(' ') : [] });
  const issues = [], theme = [];
  const ctx = await browser.newContext({ locale: 'en-US', viewport: { width: 1280, height: 860 } });
  const page = await ctx.newPage();
  page.setDefaultTimeout(8000);
  page.on('crash', () => console.log('RENDERER CRASH at ' + page.url()));
  page.on('console', (m) => { if (m.type() === 'error') issues.push(m.text() + ' @' + page.url()); });
  page.on('pageerror', (e) => issues.push('pageerror: ' + e.message + ' @' + page.url()));
  page.on('request', (r) => { if (/\/static\/assets\//.test(r.url())) theme.push(r.url()); });
  page.on('response', (r) => { if (r.status() >= 400) issues.push(r.status() + ' ' + r.url()); });
  const idle = async () => { await page.waitForLoadState('networkidle'); await sleep(150); };
  const open = async (path) => { await page.goto(admin + path); await idle(); };
  const shot = (n) => page.screenshot({ path: `${shots}/${n}.png`, fullPage: true });
  const notice = async () => { const n = page.locator('.notice:visible'); return (await n.count()) ? (await n.first().textContent()).trim() : ''; };
  // A key that was not translated shows as the key itself.
  const rawKeys = () => page.evaluate(() => {
    const out = [];
    const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (walk.nextNode()) {
      const text = walk.currentNode.textContent.trim();
      const parent = walk.currentNode.parentElement;
      if (parent.closest('script,style,template,textarea')) continue;
      if (/^[a-z0-9_]+\.[a-z0-9_.]+$/i.test(text) && !/^\d/.test(text) && !/\.(json|txt|db|log|html)$/.test(text)) out.push(text);
    }
    return [...new Set(out)];
  });
  const emptyLabels = () => page.evaluate(() => [...document.querySelectorAll('[data-i18n]')]
    .filter((e) => !e.dataset.i18n.startsWith('[') && e.offsetParent && !e.textContent.trim()).map((e) => e.dataset.i18n));
  const rowText = (name) => page.locator('tbody tr', { hasText: name });
  const save = async () => { await page.locator('form:visible button[type=submit]').first().click(); await idle(); };
  const yes = () => page.locator('dialog button').last().click();
  const del = async (name) => {
    await rowText(name).first().locator('.iconbutton').click();
    await page.locator('.menu-item', { hasText: 'Delete' }).click();
    await yes();
    await idle();
    return (await rowText(name).count()) === 0;
  };

  // First run
  await page.goto(admin); await idle();
  check('an empty database goes to setup', page.url().endsWith('/web/admin/setup'), page.url());
  await shot('admin-setup');
  await page.fill('input[name=username]', 'root'); await page.fill('input[name=password]', 'e2e-Password-1'); await page.fill('input[name=confirm_password]', 'different');
  await page.click('#sign_in_submit'); await idle();
  check('setup refuses passwords that differ', (await notice()).length > 0, await notice());
  await page.fill('input[name=username]', 'root'); await page.fill('input[name=password]', 'e2e-Password-1'); await page.fill('input[name=confirm_password]', 'e2e-Password-1');
  await page.click('#sign_in_submit'); await idle();
  check('setup signs in', !page.url().includes('/setup') && !page.url().includes('/login'), page.url());

  // Sign out and in again
  await page.click('[data-account-menu]');
  await page.locator('.menu-item', { hasText: /sign out|log ?out/i }).click(); await idle();
  check('signing out goes to login', page.url().includes('/web/admin/login'), page.url());
  await shot('admin-login');
  await page.fill('input[name=username]', 'root'); await page.fill('input[name=password]', 'wrong'); await page.click('#sign_in_submit'); await idle();
  check('wrong password shows an error', /invalid/i.test(await notice()), await notice());
  await page.fill('input[name=username]', 'root'); await page.fill('input[name=password]', 'e2e-Password-1'); await page.click('#sign_in_submit'); await idle();
  check('signs in', !page.url().includes('/login'), page.url());

  // Every page
  const pages = ['/users', '/user', '/template/user', '/groups', '/group', '/folders', '/folder', '/template/folder', '/connections', '/eventrules', '/eventrule',
    '/eventactions', '/eventaction', '/ip-lists', '/ip-list/1', '/defender', '/status', '/configs', '/maintenance', '/managers', '/manager', '/roles', '/role',
    '/api-keys', '/api-key', '/profile', '/mfa', '/changepwd'];
  for (const p of pages) {
    const before = issues.length;
    await open(p);
    const raw = await rawKeys(), blank = await emptyLabels();
    const rail = await page.locator('main h1, main .tab-title').count();
    check(`page ${p}`, issues.length === before && !raw.length && !blank.length && rail > 0, [...issues.slice(before), ...raw, ...blank].join(' | '));
    await shot('admin' + p.replace(/\//g, '-'));
  }

  // Each kind of object
  const name = (n) => `input[name=${n}]`;

  await open('/role'); await page.fill(name('name'), 'staff'); await page.fill(name('description'), 'desc'); await save();
  check('role added', page.url().endsWith('/roles') && (await rowText('staff').count()) === 1, page.url() + ' ' + (await notice()));

  await open('/group'); await page.fill(name('name'), 'team'); await save();
  check('group added', page.url().endsWith('/groups') && (await rowText('team').count()) === 1, page.url() + ' ' + (await notice()));

  await open('/folder'); await page.fill(name('name'), 'share'); await page.fill('input[name=mapped_path]', `${home}/share`); await save();
  check('folder added', page.url().endsWith('/folders') && (await rowText('share').count()) === 1, page.url() + ' ' + (await notice()));

  await open('/user');
  await page.fill(name('username'), 'bob'); await page.fill(name('password'), 'e2e-User-Pass-1'); await page.fill('input[name=home_dir]', `${home}/bob`);
  await save();
  check('user added', page.url().endsWith('/users') && (await rowText('bob').count()) === 1, page.url() + ' ' + (await notice()));
  await open('/user');
  await page.fill(name('username'), 'carol'); await page.fill(name('password'), 'e2e-User-Pass-1'); await page.fill('input[name=home_dir]', `${home}/carol`);
  await save();

  await open('/user/bob');
  check('the saved user comes back', (await page.inputValue('input[name=home_dir]')) === `${home}/bob`);
  await page.fill(name('email'), 'bob@example.com'); await page.fill(name('description'), 'edited'); await save();
  check('user edited', page.url().endsWith('/users'), page.url() + ' ' + (await notice()));
  await open('/user/bob');
  check('the edit was stored', (await page.inputValue(name('email'))) === 'bob@example.com');
  check('the stored password is not sent back', !(await page.content()).includes('$2a$') && !(await page.content()).includes('$argon2'));

  // A cloud storage user: the secret must not come back, and saving again must keep it.
  await open('/user');
  await page.fill(name('username'), 'dave'); await page.fill(name('password'), 'e2e-User-Pass-1');
  await page.locator('details', { has: page.locator('select[name=fs_provider]') }).evaluate((d) => { d.open = true; });
  await page.selectOption('select[name=fs_provider]', '1');
  check('S3 fields appear with the provider', await page.locator(name('s3_bucket')).isVisible());
  await page.fill(name('s3_bucket'), 'e2e-bucket'); await page.fill(name('s3_region'), 'eu-west-1');
  await page.fill(name('s3_access_key'), 'e2e-access'); await page.fill(name('s3_access_secret'), 'e2e-plain-secret');
  await save();
  check('S3 user added', page.url().endsWith('/users') && (await rowText('dave').count()) === 1, page.url() + ' ' + (await notice()));
  await open('/user/dave');
  check('S3 settings come back', (await page.inputValue(name('s3_bucket'))) === 'e2e-bucket' && (await page.inputValue(name('s3_region'))) === 'eu-west-1');
  check('the S3 secret is not sent back', !(await page.content()).includes('e2e-plain-secret'));
  await page.fill(name('description'), 'kept'); await save();
  check('an S3 user can be saved again', page.url().endsWith('/users'), page.url() + ' ' + (await notice()));
  const stored = await page.evaluate(async (url) => (await (await fetch(url)).json()).find((u) => u.username === 'dave'), `${admin}/users/json`);
  check('saving again keeps the S3 secret', !!(stored.filesystem && stored.filesystem.s3config && stored.filesystem.s3config.access_secret
    && stored.filesystem.s3config.access_secret.status !== '' && !JSON.stringify(stored).includes('e2e-plain-secret')), JSON.stringify(stored.filesystem || {}).slice(0, 160));

  await open('/users');
  await page.fill('.table-search', 'carol'); await sleep(100);
  check('search filters the list', (await page.locator('tbody tr').count()) === 1 && (await rowText('carol').count()) === 1);
  await page.fill('.table-search', '');
  await page.locator('thead input[type=checkbox]').check();
  check('bulk bar counts the selection', /3 items selected/.test(await page.textContent('.bulkbar')) && !(await page.textContent('.bulkbar')).includes('null'), await page.textContent('.bulkbar'));
  await page.locator('.bulkbar button', { hasText: 'Disable' }).click();
  await yes();
  await idle();
  check('bulk disable', (await page.locator('tbody tr', { hasText: 'Inactive' }).count()) === 3);

  await open('/manager');
  await page.fill(name('username'), 'helper'); await page.fill(name('password'), 'e2e-Admin-Pass-1');
  await save();
  check('admin added', page.url().endsWith('/managers') && (await rowText('helper').count()) === 1, page.url() + ' ' + (await notice()));

  await open('/api-key'); await page.fill(name('name'), 'cikey'); await save();
  check('API key shows its secret once', /^[^.]{10,}\.[^.]{10,}$/.test(await page.inputValue('#idGeneratedKey')), await notice());
  await page.reload(); await idle();
  await open('/api-keys');
  check('reloading the key page does not add another', (await rowText('cikey').count()) === 1);
  await shot('admin-apikey-created');

  await open('/ip-list/1'); await page.fill(name('ipornet'), '192.0.2.0/24'); await page.fill(name('description'), 'docs'); await save();
  check('IP entry added', page.url().includes('/ip-lists'), page.url() + ' ' + (await notice()));
  await open('/ip-lists'); await page.selectOption('#list-type', '1'); await idle();
  check('IP entry listed', (await rowText('192.0.2.0/24').count()) === 1);

  await open('/eventaction'); await page.fill(name('name'), 'act'); await page.selectOption('select[name=type]', '4'); await save();
  check('event action added', page.url().endsWith('/eventactions') && (await rowText('act').count()) === 1, page.url() + ' ' + (await notice()));

  await open('/eventrule');
  await page.fill(name('name'), 'rule'); await page.selectOption('select[name=trigger]', '6');
  await page.locator('[data-rows=actions] button', { hasText: 'Add' }).click().catch(() => {});
  await page.locator('[data-rows=actions] select').first().selectOption('act');
  await save();
  check('event rule added', page.url().endsWith('/eventrules') && (await rowText('rule').count()) === 1, page.url() + ' ' + (await notice()));
  await rowText('rule').first().locator('.iconbutton').click();
  await page.locator('.menu-item', { hasText: 'Run' }).click();
  await yes();
  await sleep(600);
  check('on demand rule runs', /started|ok/i.test(await page.textContent('#toasts')), await page.textContent('#toasts'));

  await open('/configs');
  await page.locator('[data-tab=pane-branding]').click();
  await page.fill('input[name=branding_webadmin_short_name]', 'MyNAS');
  await page.locator('#pane-branding button[type=submit]').click(); await idle();
  check('branding saved', (await page.textContent('.brand')).includes('MyNAS'), await page.textContent('.brand'));

  await open('/status'); await shot('admin-status-after');
  await open('/maintenance');
  const [download] = await Promise.all([page.waitForEvent('download'), page.locator('main a[href*=backup], main form:has(a) a').first().click()]).catch((e) => [null]);
  check('backup downloads', !!download);

  // Removing
  await open('/eventrules'); check('rule deleted', await del('rule'));
  await open('/eventactions'); check('action deleted', await del('act'));
  await open('/api-keys'); check('API key deleted', await del('cikey'));
  await open('/managers'); check('admin deleted', await del('helper'));
  check('own admin cannot be deleted', await (async () => {
    await rowText('root').first().locator('.iconbutton').click();
    const n = await page.locator('.menu-item', { hasText: 'Delete' }).count(); await page.keyboard.press('Escape'); return n === 0;
  })());
  await open('/users'); check('user deleted', await del('bob'));
  check('S3 user deleted', await del('dave'));
  await open('/folders'); check('folder deleted', await del('share'));
  await open('/groups'); check('group deleted', await del('team'));
  await open('/roles'); check('role deleted', await del('staff'));

  // Two-factor authentication for the admin
  await open('/mfa');
  await page.click('#generate'); await idle();
  const secret = (await page.textContent('.secret')).trim();
  await page.fill('dialog input', totp(secret)); await page.click('dialog [data-submit]'); await sleep(800); await idle();
  await open('/mfa');
  check('two-factor is on', (await page.locator('#disable').count()) === 1);
  await page.click('[data-account-menu]');
  await page.locator('.menu-item', { hasText: /sign out|log ?out/i }).click(); await idle();
  await page.fill('input[name=username]', 'root'); await page.fill('input[name=password]', 'e2e-Password-1'); await page.click('#sign_in_submit'); await idle();
  check('login asks for the code', page.url().includes('/twofactor'), page.url());
  await shot('admin-twofactor');
  await sleep(Math.max(0, 31000 - (Date.now() % 30000)));
  await page.fill('input[name=passcode]', totp(secret)); await page.click('#sign_in_submit'); await idle();
  check('the code signs in', !page.url().includes('/twofactor') && !page.url().includes('/login'), page.url() + ' ' + (await notice()));
  await open('/mfa');
  await page.click('#disable'); await sleep(200); await yes(); await sleep(800); await idle();
  await open('/mfa');
  check('two-factor can be turned off', (await page.locator('#disable').count()) === 0);

  // The small screen
  await page.setViewportSize({ width: 390, height: 800 });
  await open('/users');
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check('no sideways scroll on a phone', overflow <= 0, overflow);
  await page.click('[data-rail-toggle]'); await sleep(250); await shot('admin-phone-menu');
  check('the menu opens on a phone', await page.locator('#rail a').first().isVisible());

  check('nothing loaded from the old theme', theme.length === 0, theme.join(' '));
  check('no console errors or failed requests', issues.length === 0, issues.slice(0, 10).join(' | '));
  await browser.close();
  console.log(failed ? `\n${failed} FAILED` : '\nALL PASSED');
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
