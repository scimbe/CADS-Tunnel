// Cookie parser and colour choice of the login theme's optional "My Daily Idea" look
// (docker/deploy/keycloak/themes/ct-bunsenbrenner/login/resources/js/ct-look.js).
//   node --test scripts/keycloak-ct-look.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const look = require('../docker/deploy/keycloak/themes/ct-bunsenbrenner/login/resources/js/ct-look.js');

test('valid cookie yields both colours', () => {
  assert.deepEqual(look.parseCookie('ct_look=daily.ffd400.ff3b1d'), { a: '#ffd400', b: '#ff3b1d' });
  assert.deepEqual(look.parseCookie('x=1; ct_look=daily.1b2a6b.ff7a00; y=2'), { a: '#1b2a6b', b: '#ff7a00' });
  assert.deepEqual(look.parseCookie('KEYCLOAK_LOCALE=de;ct_look=daily.000000.ffffff'), { a: '#000000', b: '#ffffff' });
});

test('absent or empty cookie yields null', () => {
  for (const h of ['', 'a=1; b=2', 'ct_looks=daily.ffd400.ff3b1d', 'xct_look=daily.ffd400.ff3b1d', 'ct_look=', 'ct_look', undefined, null, 42]) {
    assert.equal(look.parseCookie(h), null, String(h));
  }
});

test('anything but the strict lowercase format is rejected', () => {
  for (const v of [
    'daily.FFD400.ff3b1d',          // upper case
    'daily.ffd400.ff3b1',           // too short
    'daily.ffd400.ff3b1d0',         // too long
    'daily.ffd400',                 // one colour
    'daily.ffd400.ff3b1d.000000',   // extra part
    'Daily.ffd400.ff3b1d',
    'night.ffd400.ff3b1d',
    'daily.#ffd400.#ff3b1d',
    'daily.ffd40g.ff3b1d',          // non-hex
    '"daily.ffd400.ff3b1d"',        // quoted
    'daily%2Effd400%2Eff3b1d',      // url-encoded
    ' daily.ffd400.ff3b1d',
    'daily.ffd400.ff3b1d ',
    'daily.ffd400.ff3b1d\n',
  ]) assert.equal(look.parseCookie('ct_look=' + v), null, JSON.stringify(v));
});

test('injection attempts are rejected', () => {
  for (const v of [
    'daily.ffd400.ff3b1d"><script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    'daily.ffd400.ff3b1d}html{background:url(//evil)}',
    'daily.ffd400.red',
    'daily.ffd400.ff3b1d\u0000',
    'daily.ffd400.expression(alert(1))',
  ]) assert.equal(look.parseCookie('ct_look=' + v), null, JSON.stringify(v));
  // header split on ';' -- the trailing part is a separate (ignored) cookie, colours stay hex
  for (const h of ['ct_look=daily.ffd400.ff3b1d; style=color:red', 'ct_look=daily.ffd400.ff3b1d;--d-a:url(javascript:alert(1))'])
    assert.deepEqual(look.parseCookie(h), { a: '#ffd400', b: '#ff3b1d' }, h);
});

test('first ct_look decides; an invalid first one switches the look off', () => {
  assert.equal(look.parseCookie('ct_look=bogus; ct_look=daily.ffd400.ff3b1d'), null);
  assert.deepEqual(look.parseCookie('ct_look=daily.ffd400.ff3b1d; ct_look=daily.000000.000000'), { a: '#ffd400', b: '#ff3b1d' });
});

// Two fixed inks cannot give 4.5:1 on every colour: at the crossover luminance both reach only
// ~4.25:1. The CSS keeps body text off colour a for that reason; here: the chosen ink is never
// below that floor (>= 3:1 large text everywhere) and reaches 4.5:1 outside the mid-tone band.
test('ink on any colour >= 4.25:1 (4.5:1 outside luminance 0.15-0.22); button text on #111 >= 4.5:1', () => {
  const pairs = ['ffd400', 'ff3b1d', '1b2a6b', 'ff7a00', '000000', 'ffffff', '777777', '808080', '00a0ff', 'ff00ff', '2e8b57'];
  for (let i = 0; i < 4096; i++) pairs.push(((i * 2654435761) >>> 8 & 0xffffff).toString(16).padStart(6, '0'));
  for (const h of pairs) {
    const c = '#' + h;
    const r = look.contrast(c, look.ink(c)), L = look.lum(c);
    assert.ok(r >= 4.25, `${c} ink ${look.ink(c)} ${r.toFixed(2)}`);
    if (L < 0.15 || L > 0.22) assert.ok(r >= 4.5, `${c} (L=${L.toFixed(3)}) ink ${look.ink(c)} ${r.toFixed(2)}`);
    assert.ok(look.contrast('#111111', look.btn(c)) >= 4.5, `${c} btn ${look.btn(c)}`);
  }
});

test('known pairs: defaults and a dark pair', () => {
  assert.equal(look.ink('#ffd400'), '#111111');
  assert.equal(look.ink('#ff3b1d'), '#111111');   // a fixed lum>0.45 cut-off would give #fffaf0 at 3.4:1
  assert.equal(look.ink('#1b2a6b'), '#fffaf0');
  assert.equal(look.ink('#ff7a00'), '#111111');   // cut-off would give #fffaf0 at 2.6:1
  assert.equal(look.btn('#ffd400'), '#ffd400');
  assert.equal(look.btn('#1b2a6b'), '#fffaf0');
});

test('apply sets attribute and variables only via setProperty', () => {
  const mk = cookie => {
    const props = {}, attrs = {};
    return { props, attrs, doc: { cookie, documentElement: {
      style: { setProperty: (k, v) => { props[k] = v; } },
      setAttribute: (k, v) => { attrs[k] = v; },
    } } };
  };
  const on = mk('ct_look=daily.1b2a6b.ff7a00');
  assert.ok(look.apply(on.doc));
  assert.deepEqual(on.attrs, { 'data-look': 'daily' });
  assert.deepEqual(on.props, { '--d-a': '#1b2a6b', '--d-b': '#ff7a00', '--d-on': '#fffaf0', '--d-onb': '#111111', '--d-btn': '#fffaf0' });
  const off = mk('ct_look=daily.1b2a6b.ff7a00<x>');
  assert.equal(look.apply(off.doc), null);
  assert.deepEqual(off.attrs, {});
  assert.deepEqual(off.props, {});
  const throwing = { get cookie() { throw new Error('blocked'); }, documentElement: null };
  assert.equal(look.apply(throwing), null);
});
