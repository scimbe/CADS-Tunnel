// Systematischer Kontrast-Durchlauf über alle erreichbaren Keycloak-Seiten.
// Misst jeden Textknoten gegen seinen ersten opaken Hintergrund und meldet
// alles unter 4.5:1 (WCAG AA für normalen Text; 3:1 wäre die Grenze für große).
import { chromium } from 'playwright';

const KC = 'https://auth.bunsenbrenner.org/realms/ct-demo';
const AUTH = `${KC}/protocol/openid-connect/auth?client_id=ct-portal&redirect_uri=https%3A%2F%2Fbunsenbrenner.org%2Fportal%2Fcallback&response_type=code&scope=openid`;
const EMAIL = 'ui-sweep-probe@example.org', PASS = 'UiSweep!2026x';

const rgb = s => (s || '').match(/\d+/g)?.slice(0, 3).map(Number) ?? null;
const lum = c => { const f = c.map(v => { v /= 255; return v <= .03928 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4; }); return .2126 * f[0] + .7152 * f[1] + .0722 * f[2]; };
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + .05) / (y + .05); };

const measure = async (page, label) => {
  const rows = await page.evaluate(() => {
    const out = [];
    const opaque = v => { const m = v.match(/rgba?\(([^)]+)\)/); if (!m) return false; const p = m[1].split(',').map(Number); return p.length < 4 || p[3] >= 0.95; };
    document.querySelectorAll('body *').forEach(c => {
      // Direkter Textinhalt statt innerText des ganzen Teilbaums, und KEIN
      // "nur Blattelemente"-Filter: ein <a> mit <span> darin wurde damit
      // uebersprungen, was zu einer Entwarnung fuehrte, die den Zustand nie
      // angesehen hatte (Sprachmenue, 16.08.). Ein Element zaehlt, sobald es
      // eigenen Text traegt.
      const t = [...c.childNodes].filter(n => n.nodeType === 3).map(n => n.textContent).join('').trim();
      if (!t || t.length > 70) return;
      const cs = getComputedStyle(c);
      if (cs.visibility === 'hidden' || cs.display === 'none' || parseFloat(cs.opacity) < .1) return;
      let bg = 'rgba(0, 0, 0, 0)', p = c;
      while (p && !opaque(bg)) { bg = getComputedStyle(p).backgroundColor; p = p.parentElement; }
      out.push({ t: t.slice(0, 38), fg: cs.color, bg, cls: (c.className || '').toString().slice(0, 40), px: parseFloat(cs.fontSize), bold: parseInt(cs.fontWeight) >= 700 });
    });
    return out;
  });
  const seen = new Set(); const bad = [];
  for (const r of rows) {
    const k = r.fg + r.bg + r.cls; if (seen.has(k)) continue; seen.add(k);
    const f = rgb(r.fg), g = rgb(r.bg); if (!f || !g) continue;
    const c = ratio(f, g);
    // Großer Text (>=24px, oder >=18.66px fett) darf laut WCAG AA bei 3:1 liegen.
    const limit = (r.px >= 24 || (r.px >= 18.66 && r.bold)) ? 3 : 4.5;
    if (c < limit) bad.push(`${c.toFixed(2).padStart(6)}:1 (Grenze ${limit})  "${r.t}"  fg=${r.fg} bg=${r.bg} ${r.px}px  .${r.cls}`);
  }
  console.log(`\n### ${label}  (${rows.length} Textknoten)`);
  if (!bad.length) console.log('   keine Beanstandung');
  else bad.forEach(b => console.log('   ' + b));
};

const browser = await chromium.launch();
const page = await browser.newPage({ ignoreHTTPSErrors: true, viewport: { width: 1400, height: 950 } });

await page.goto(AUTH, { waitUntil: 'networkidle' });
await measure(page, 'Anmeldung');

for (const [label, sel] of [['Registrierung', 'a[href*="registration"]'], ['Passwort vergessen', 'a[href*="reset-credentials"]']]) {
  await page.goto(AUTH, { waitUntil: 'networkidle' });
  if (await page.locator(sel).count()) { await page.locator(sel).first().click(); await page.waitForLoadState('networkidle'); await measure(page, label); }
  else console.log(`\n### ${label}: Link nicht vorhanden`);
}

await page.goto(`${KC}/account/`, { waitUntil: 'domcontentloaded' });
await page.waitForSelector('input[name="username"], #username', { timeout: 20000 }).catch(() => {});
if (await page.locator('input[name="username"], #username').count()) {
  await page.fill('input[name="username"], #username', EMAIL);
  await page.fill('input[name="password"], #password', PASS);
  await page.click('input[type="submit"], #kc-login');
  await page.waitForLoadState('networkidle');
  if (await page.locator('input[name="accept"], #kc-accept').count()) { await page.click('input[name="accept"], #kc-accept').catch(()=>{}); await page.waitForLoadState('networkidle'); }
}
for (const [label, path] of [
  ['Konto: Persönliche Daten', 'account/'],
  ['Konto: Anmeldung', 'account/account-security/signing-in'],
  ['Konto: Geräteaktivität', 'account/account-security/device-activity'],
  ['Konto: Verknüpfte Konten', 'account/account-security/linked-accounts'],
  ['Konto: Anwendungen', 'account/applications'],
]) {
  await page.goto(`${KC}/${path}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1800);
  await measure(page, label);
}
await browser.close();
