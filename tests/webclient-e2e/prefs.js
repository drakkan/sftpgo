// Usage: node prefs.js BASE SHOTS
const { chromium } = require('playwright');
const [base, shots] = process.argv.slice(2);
let failed = 0;
const check = (n, ok, x = '') => { if (!ok) failed++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${x !== '' ? '  -> ' + String(x).slice(0, 220) : ''}`); };
const NAMES = { en: 'English', pl: 'Polski', de: 'Deutsch', 'zh-CN': '简体中文' };
const pick = async (page, code) => { await page.click('[data-language-picker]'); await page.locator(`[role=menuitemradio][lang="${code}"]`).click(); await page.waitForTimeout(300); };
const langs = (list) => `Object.defineProperty(navigator,'languages',{get:()=>${JSON.stringify(list)}});Object.defineProperty(navigator,'language',{get:()=>${JSON.stringify(list[0])}});`;
const open = async (browser, list, extra = '') => {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 860 } });
  await ctx.addInitScript(langs(list) + extra);
  const page = await ctx.newPage(); page.setDefaultTimeout(8000);
  await page.goto(`${base}/web/client/login`, { waitUntil: 'networkidle' });
  return { ctx, page, lang: () => page.evaluate(() => i18next.resolvedLanguage), picker: () => page.textContent('[data-language-name]'), saved: () => page.evaluate(() => localStorage.getItem('webclient-language')) };
};
(async () => {
  const browser = await chromium.launch();
  const errors = [];
  // Configured: en, pl, de, zh-CN
  for (const [list, want, why] of [
    [['pl-PL'], 'pl', 'regional code alone'],
    [['pl-PL', 'pl', 'en-US', 'en'], 'pl', 'typical Polish Chrome'],
    [['pl'], 'pl', 'plain code'],
    [['en-GB', 'pl'], 'en', 'browser order wins over an exact match further down'],
    [['fr-FR', 'de-AT', 'pl'], 'de', 'skips a language that is not offered'],
    [['fr-FR', 'ja'], 'en', 'nothing offered falls back to the first configured'],
    [['zh-TW'], 'zh-CN', 'matches on the language part'],
    [['ZH-cn'], 'zh-CN', 'ignores case'],
  ]) {
    const v = await open(browser, list);
    const got = await v.lang();
    check(`${list.join(',')} -> ${want} (${why})`, got === want && (await v.picker()) === NAMES[want] && (await v.saved()) === null, `${got}, saved ${await v.saved()}`);
    await v.ctx.close();
  }
  // What the earlier build saved automatically must no longer count as a choice
  let v = await open(browser, ['pl-PL'], `try{localStorage.setItem('i18nextLng','en')}catch(e){}`);
  check('an automatically saved language is ignored', await v.lang() === 'pl' && (await v.page.textContent('button[type=submit]')).includes('Zaloguj'), await v.lang());
  await v.ctx.close();
  // A deliberate choice beats the browser, and only then is anything stored
  v = await open(browser, ['pl-PL']);
  v.page.on('pageerror', (e) => errors.push(e.message));
  await pick(v.page, 'de');
  check('picking saves the choice', await v.saved() === 'de' && await v.lang() === 'de');
  await v.page.reload({ waitUntil: 'networkidle' });
  check('choice beats the browser after a reload', await v.lang() === 'de' && await v.picker() === 'Deutsch');
  await v.page.goto(`${base}/web/client/files`, { waitUntil: 'networkidle' });
  await v.page.fill('input[name=username]', 'alice'); await v.page.fill('input[name=password]', 'e2e-User-Pass-1'); await v.page.click('#sign_in_submit'); await v.page.waitForLoadState('networkidle'); await v.page.waitForTimeout(400);
  check('choice carries past sign-in', await v.lang() === 'de');
  await pick(v.page, 'en');
  const page = v.page;

  // Theme dropdown
  const button = page.locator('[data-theme-picker]');
  const item = (name) => page.locator('[role=menuitemradio]', { hasText: name });
  const theme = () => page.evaluate(() => [document.documentElement.dataset.themeChoice, document.documentElement.dataset.theme].join());
  const before = await theme();
  await button.click();
  check('clicking opens a menu instead of switching', await page.locator('.menu').isVisible() && await theme() === before, before);
  check('three choices', (await page.locator('[role=menuitemradio]').allTextContents()).join() === 'Auto,Light,Dark');
  check('current choice is marked', await item('Auto').getAttribute('aria-checked') === 'true' && await item('Auto').locator('.menu-check').count() === 1);
  check('button says it opens a menu', await button.getAttribute('aria-expanded') === 'true');
  await page.screenshot({ path: `${shots}/theme-menu.png` });
  await button.click();
  check('clicking again closes it', await page.locator('.menu').count() === 0);
  await button.click(); await item('Dark').click();
  check('dark applies straight away', await theme() === 'dark,dark' && await page.locator('.menu').count() === 0);
  check('no toast on choosing', await page.locator('.toast').count() === 0);
  check('button shows the chosen theme', (await button.locator('use').getAttribute('href')).endsWith('#moon'));
  await page.reload({ waitUntil: 'networkidle' });
  check('theme survives a reload', await theme() === 'dark,dark' && (await button.locator('use').getAttribute('href')).endsWith('#moon'));
  await button.click();
  check('marked item follows', await item('Dark').getAttribute('aria-checked') === 'true' && await item('Auto').getAttribute('aria-checked') === 'false');
  check('focus starts on the current item', await page.evaluate(() => document.activeElement.textContent) === 'Dark');
  await page.screenshot({ path: `${shots}/theme-menu-dark.png` });
  await page.keyboard.press('ArrowUp'); await page.keyboard.press('Enter'); await page.waitForTimeout(150);
  check('keyboard: arrows and Enter pick', await theme() === 'light,light', await theme());
  await button.click(); await page.keyboard.press('Escape');
  check('Escape closes and returns focus', await page.locator('.menu').count() === 0 && await page.evaluate(() => document.activeElement.hasAttribute('data-theme-picker')));
  await button.click(); await item('Auto').click();
  await page.emulateMedia({ colorScheme: 'dark' }); await page.waitForTimeout(150);
  check('Auto follows the system', await theme() === 'auto,dark', await theme());
  await page.emulateMedia({ colorScheme: 'light' }); await page.waitForTimeout(150);
  check('and changes with it', await theme() === 'auto,light', await theme());
  await pick(page, 'pl');
  await button.click();
  check('menu is translated', (await page.locator('[role=menuitemradio]').allTextContents()).join() === 'Automatyczny,Jasny,Ciemny');
  await page.keyboard.press('Escape');
  await page.setViewportSize({ width: 390, height: 844 }); await page.waitForTimeout(150);
  await button.click();
  const box = await page.locator('.menu').boundingBox();
  check('menu fits on a phone', box.x >= 0 && box.x + box.width <= 390, JSON.stringify(box));
  await page.screenshot({ path: `${shots}/theme-menu-phone.png` });
  await page.keyboard.press('Escape');
  await page.setViewportSize({ width: 1280, height: 860 }); await page.waitForTimeout(150);

  // Language dropdown behaves like the theme dropdown
  const lang = page.locator('.bar [data-language-picker]');
  const cursor = (l) => l.evaluate((n) => getComputedStyle(n).cursor);
  check('hand cursor on the button', await cursor(lang) === 'pointer');
  await lang.click();
  const options = page.locator('[role=menuitemradio]');
  check('all configured languages listed', (await options.allTextContents()).join().replace(/\s/g, '') === 'English,Polski,Deutsch,简体中文', (await options.allTextContents()).join());
  let hands = true;
  for (let i = 0; i < await options.count(); i++) { await options.nth(i).hover(); hands = hands && await cursor(options.nth(i)) === 'pointer'; }
  check('hand cursor on every option', hands);
  check('current language marked and focused', await page.locator('[role=menuitemradio][lang=pl]').getAttribute('aria-checked') === 'true' && await page.evaluate(() => document.activeElement.lang) === 'pl');
  check('each option declares its own language', await page.locator('[role=menuitemradio][lang=de]').count() === 1);
  await page.screenshot({ path: `${shots}/language-menu.png` });
  await lang.click();
  check('clicking again closes it', await page.locator('.menu').count() === 0);
  await lang.click(); await page.keyboard.press('ArrowDown'); await page.keyboard.press('Enter'); await page.waitForTimeout(300);
  check('keyboard picks the next language', await page.evaluate(() => i18next.resolvedLanguage) === 'de' && await page.evaluate(() => localStorage.getItem('webclient-language')) === 'de');
  check('button shows the language', (await page.textContent('[data-language-name]')) === 'Deutsch');
  await lang.click(); await page.keyboard.press('Escape');
  check('Escape returns focus to the button', await page.evaluate(() => document.activeElement.hasAttribute('data-language-picker')));

  // Sign-in page, where it sits low on a phone
  const low = await browser.newContext({ viewport: { width: 390, height: 600 }, isMobile: true, hasTouch: true });
  await low.addInitScript(langs(['pl-PL']));
  const m = await low.newPage(); m.setDefaultTimeout(8000);
  await m.goto(`${base}/web/client/login`, { waitUntil: 'networkidle' });
  await m.locator('[data-language-picker]').tap(); await m.waitForTimeout(150);
  const mb = await m.locator('.menu').boundingBox();
  check('menu stays on screen on the sign-in page', mb.y >= 0 && mb.y + mb.height <= 600 && mb.x >= 0 && mb.x + mb.width <= 390, JSON.stringify(mb));
  await m.screenshot({ path: `${shots}/language-menu-login.png` });
  await m.locator('[role=menuitemradio][lang=de]').tap(); await m.waitForTimeout(350);
  check('tapping an option works on a phone', await m.evaluate(() => i18next.resolvedLanguage) === 'de');
  await low.close();
  check('no script errors', errors.length === 0, errors.join(' | '));
  await browser.close();
  console.log(failed ? `FAILED ${failed}` : 'ALL PASS');
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error('CRASH', e); process.exit(2); });
