// The sign-in look follows the calling Keycloak client (client attribute login_theme), never a
// cookie. A cookie on Domain=bunsenbrenner.org (the former ct_look, #890) reaches every login
// of the realm and so leaked the web conference's look into the bunsenbrenner.org sign-in.
//   node --test scripts/keycloak-theme-per-client.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const THEMES = join(ROOT, 'docker/deploy/keycloak/themes');
const REALM = join(ROOT, 'docker/deploy/keycloak/ct-demo-realm.json');

function files(dir) {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? files(p) : [p];
  });
}

test('no login theme reads cookies', () => {
  for (const p of files(THEMES).filter((f) => /\.(js|ftl)$/.test(f))) {
    assert.doesNotMatch(readFileSync(p, 'utf8'), /document\.cookie|ct_look/, p);
  }
});

test('no login theme loads a script', () => {
  for (const t of readdirSync(THEMES)) {
    const p = join(THEMES, t, 'login/theme.properties');
    let s;
    try { s = readFileSync(p, 'utf8'); } catch { continue; }
    assert.doesNotMatch(s, /^\s*scripts\s*=/m, p);
  }
});

test('the look is chosen per client in the realm', () => {
  const realm = JSON.parse(readFileSync(REALM, 'utf8'));
  const theme = Object.fromEntries(
    realm.clients.map((c) => [c.clientId, (c.attributes || {}).login_theme ?? null]),
  );
  assert.equal(theme.mydailyidea, 'ct-mydailyidea');
  assert.equal(theme['praktikum-creator'], 'ct-riisc');
  // bunsenbrenner.org's own portal uses the realm default (ct-bunsenbrenner).
  assert.equal(theme['ct-portal'], null);
  assert.equal(realm.loginTheme, 'ct-bunsenbrenner');
});
