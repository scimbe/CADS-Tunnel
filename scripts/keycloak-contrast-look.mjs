// Kontrast-Durchlauf fuer den optionalen "My Daily Idea"-Look der Anmeldeseiten
// (Cookie ct_look=daily.RRGGBB.RRGGBB, siehe login/resources/js/ct-look.js).
// Gleiche Messung wie keycloak-contrast-sweep.mjs (jeder Textknoten gegen seinen ersten
// opaken Hintergrund, WCAG AA 4.5:1, grosser Text 3:1), zusaetzlich mit den Zustaenden,
// die ein statischer Blick nie sieht: Platzhalter, Fokus, Hover und gesperrter Knopf,
// Fehlermeldung nach falschem Login, Feldfehler der Registrierung, Fehlerseite,
// aufgeklapptes Sprachmenue. Ohne Cookie und mit ungueltigem Cookie muss die Seite
// pixelgleich bleiben -- das prueft der Vergleich der beiden Bildschirmfotos.
//
//   KC=https://auth.bunsenbrenner.org/realms/ct-demo CLIENT=ct-portal \
//   REDIRECT=https://bunsenbrenner.org/portal/callback SHOTS=/tmp/kc node scripts/keycloak-contrast-look.mjs
//   CHROME=/path/to/chrome  optional, sonst Playwrights eigenes Chromium.
// Exit-Code 1, sobald ein Paar im Daily-Look unter der Grenze liegt.
import { chromium } from 'playwright';
import { mkdirSync, readFileSync } from 'node:fs';

const KC = process.env.KC || 'https://auth.bunsenbrenner.org/realms/ct-demo';
const CLIENT = process.env.CLIENT || 'ct-portal';
const REDIRECT = process.env.REDIRECT || 'https://bunsenbrenner.org/portal/callback';
const SHOTS = process.env.SHOTS || '';
const AUTH = `${KC}/protocol/openid-connect/auth?client_id=${encodeURIComponent(CLIENT)}&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&scope=openid`;
const ERROR_PAGE = `${KC}/protocol/openid-connect/auth?client_id=kein-solcher-client&redirect_uri=${encodeURIComponent(REDIRECT)}&response_type=code&scope=openid`;
if (SHOTS) mkdirSync(SHOTS, { recursive: true });

const rgb = s => (s || '').match(/[\d.]+/g)?.slice(0, 3).map(Number) ?? null;
const lum = c => { const f = c.map(v => { v /= 255; return v <= .03928 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4; }); return .2126 * f[0] + .7152 * f[1] + .0722 * f[2]; };
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + .05) / (y + .05); };

// Liefert alle Textknoten (eigener Text, sichtbar) plus Platzhalter der Eingabefelder.
const collect = page => page.evaluate(() => {
  const out = [];
  const opaque = v => { const m = v.match(/rgba?\(([^)]+)\)/); if (!m) return false; const p = m[1].split(',').map(Number); return p.length < 4 || p[3] >= 0.95; };
  const bgOf = el => { let bg = 'rgba(0, 0, 0, 0)', p = el; while (p && !opaque(bg)) { bg = getComputedStyle(p).backgroundColor; p = p.parentElement; } return opaque(bg) ? bg : 'rgb(255, 255, 255)'; };
  const visible = (el, cs) => { const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none' && parseFloat(cs.opacity) >= .1; };
  document.querySelectorAll('body *').forEach(c => {
    const cs = getComputedStyle(c);
    let t = [...c.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent).join('').trim();
    if (!t && c.tagName === 'INPUT' && /^(submit|button)$/.test(c.type)) t = c.value;   // <input type=submit value=...>
    if (t && t.length <= 70 && visible(c, cs))
      out.push({ t: t.slice(0, 38), fg: cs.color, bg: bgOf(c), sel: c.tagName.toLowerCase() + (c.id ? '#' + c.id : '') + '.' + (c.className || '').toString().split(' ').slice(0, 3).join('.'), px: parseFloat(cs.fontSize), bold: parseInt(cs.fontWeight) >= 700 });
    if (c.tagName === 'INPUT' && c.placeholder && visible(c, cs)) {
      const ps = getComputedStyle(c, '::placeholder');
      out.push({ t: 'placeholder: ' + c.placeholder.slice(0, 26), fg: ps.color, bg: bgOf(c), sel: 'input#' + c.id + '::placeholder', px: parseFloat(ps.fontSize), bold: false });
    }
  });
  return out;
});

let failures = 0;
const measure = async (page, label, strict) => {
  const rows = await collect(page);
  const seen = new Set(); const bad = []; let min = Infinity, minRow = null;
  for (const r of rows) {
    const k = r.fg + r.bg + r.sel; if (seen.has(k)) continue; seen.add(k);
    const f = rgb(r.fg), g = rgb(r.bg); if (!f || !g) continue;
    const c = ratio(f, g);
    const limit = (r.px >= 24 || (r.px >= 18.66 && r.bold)) ? 3 : 4.5;
    if (c / limit < min) { min = c / limit; minRow = `${c.toFixed(2)}:1 (Grenze ${limit}) "${r.t}"`; }
    if (c < limit) bad.push(`${c.toFixed(2).padStart(6)}:1 (Grenze ${limit})  "${r.t}"  fg=${r.fg} bg=${r.bg} ${r.px}px  ${r.sel}`);
  }
  console.log(`\n### ${label}  (${rows.length} Textknoten; knappstes Paar: ${minRow ?? '-'})`);
  if (!bad.length) console.log('   keine Beanstandung');
  else { bad.forEach(b => console.log('   ' + b)); if (strict) failures += bad.length; }
};

const LOOKS = [
  ['normal', null],
  ['ungueltig', 'daily.FFD400.ff3b1d'],
  ['daily-gelb', 'daily.ffd400.ff3b1d'],
  ['daily-dunkel', 'daily.1b2a6b.ff7a00'],
  // Mittelton (Luminanz ~0.19): hier erreicht keine der beiden Tinten 4.5:1, also darf
  // direkt auf Farbe a nur grosser Text stehen.
  ['daily-mitte', 'daily.7a7a7a.2e8b57'],
];

const browser = await chromium.launch(process.env.CHROME ? { executablePath: process.env.CHROME } : {});
for (const [name, cookie] of LOOKS) {
  const strict = name.startsWith('daily');
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 1000 }, locale: 'de-DE', reducedMotion: 'reduce' });
  if (cookie) await ctx.addCookies([{ name: 'ct_look', value: cookie, url: new URL(KC).origin }]);
  const page = await ctx.newPage();
  const shot = async what => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/kc-${what}-${name}.png`, fullPage: true }); };
  const look = async () => page.evaluate(() => document.documentElement.getAttribute('data-look'));

  console.log(`\n================ ${name}${cookie ? ' (ct_look=' + cookie + ')' : ''} ================`);
  await page.goto(AUTH, { waitUntil: 'networkidle' });
  await page.evaluate(() => document.fonts.ready);
  console.log(`data-look=${await look()}`);
  await measure(page, `${name}: Anmeldung`, strict); await shot('login');

  // Zustaende auf der Anmeldeseite
  await page.focus('#username'); await measure(page, `${name}: Anmeldung, Feld fokussiert`, strict);
  await page.hover('#kc-login'); await measure(page, `${name}: Anmeldung, Knopf hover`, strict);
  await page.evaluate(() => document.querySelector('#kc-login').setAttribute('disabled', ''));
  await measure(page, `${name}: Anmeldung, Knopf gesperrt`, strict);
  await page.evaluate(() => document.querySelector('#kc-login').removeAttribute('disabled'));
  if (await page.locator('#kc-current-locale-link').count()) {
    await page.click('#kc-current-locale-link'); await page.waitForTimeout(300);
    await measure(page, `${name}: Sprachmenue aufgeklappt`, strict);
  }

  await page.goto(AUTH, { waitUntil: 'networkidle' });
  await page.fill('#username', 'nicht-existent@example.org'); await page.fill('#password', 'falsch');
  await page.click('#kc-login'); await page.waitForLoadState('networkidle');
  await measure(page, `${name}: Fehlermeldung nach falschem Login`, strict); await shot('login-error');

  await page.goto(AUTH, { waitUntil: 'networkidle' });
  const reg = page.locator('a[href*="registration"]');
  if (await reg.count()) {
    await reg.first().click(); await page.waitForLoadState('networkidle');
    await page.evaluate(() => document.fonts.ready);
    await measure(page, `${name}: Registrierung`, strict); await shot('register');
    await page.click('#kc-form-buttons [type="submit"]'); await page.waitForLoadState('networkidle');
    await measure(page, `${name}: Registrierung, leer abgeschickt`, strict); await shot('register-errors');
  } else console.log(`\n### ${name}: Registrierungslink nicht vorhanden`);

  await page.goto(AUTH, { waitUntil: 'networkidle' });
  const reset = page.locator('a[href*="reset-credentials"]');
  if (await reset.count()) { await reset.first().click(); await page.waitForLoadState('networkidle'); await measure(page, `${name}: Passwort vergessen`, strict); }

  await page.goto(ERROR_PAGE, { waitUntil: 'networkidle' });
  await measure(page, `${name}: Fehlerseite (unbekannter Client)`, strict); await shot('error');
  await ctx.close();
}
await browser.close();

if (SHOTS) {
  // Ohne Cookie und mit ungueltigem Cookie muss die Seite identisch aussehen.
  for (const what of ['login', 'register', 'error']) {
    try {
      const same = Buffer.compare(readFileSync(`${SHOTS}/kc-${what}-normal.png`), readFileSync(`${SHOTS}/kc-${what}-ungueltig.png`)) === 0;
      console.log(`\n${what}: normal vs. ungueltiges Cookie ${same ? 'pixelgleich' : 'UNTERSCHIEDLICH'}`);
      if (!same) failures++;
    } catch { /* Seite nicht erreicht */ }
  }
}
console.log(`\n${failures ? failures + ' Beanstandung(en) im Daily-Look' : 'Daily-Look: alle Paare ueber der WCAG-AA-Grenze'}`);
process.exit(failures ? 1 : 0);
