/* Optional "My Daily Idea" look for the sign-in pages.
 *
 * The web conference in that look sets a cookie on the parent domain:
 *   ct_look=daily.RRGGBB.RRGGBB   (lowercase hex; background colour a, accent colour b)
 * Domain=bunsenbrenner.org, so auth.bunsenbrenner.org receives it. Anything else -- no
 * cookie, another value, upper case, quotes, extra parts -- leaves the page exactly as it
 * is without the cookie: no attribute, no variables, css/ct-daily.css matches nothing.
 *
 * The cookie value never reaches the DOM as markup. Only the two validated hex colours
 * are used, and only through style.setProperty. Loaded as a classic <script> in <head>
 * (theme.properties `scripts=`), so the attribute is set before the body is painted.
 */
(function (root) {
  'use strict';

  var NAME = 'ct_look';
  var VALUE = /^daily\.([0-9a-f]{6})\.([0-9a-f]{6})$/;
  var INK = '#111111';
  var PAPER = '#fffaf0';

  // "a=1; ct_look=daily.ffd400.ff3b1d" -> {a:'#ffd400', b:'#ff3b1d'} or null.
  // The first cookie named ct_look decides; an invalid one is not skipped in favour of a
  // later one, so a stray value can only switch the look off, never pick colours.
  function parseCookie(header) {
    if (typeof header !== 'string' || !header) return null;
    var parts = header.split(';');
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i].replace(/^\s+/, '');   // only the separator space; the value must match exactly
      var eq = p.indexOf('=');
      if (eq < 0 || p.slice(0, eq) !== NAME) continue;
      var m = VALUE.exec(p.slice(eq + 1));
      return m ? { a: '#' + m[1], b: '#' + m[2] } : null;
    }
    return null;
  }

  // WCAG 2.x relative luminance of #rrggbb.
  function lum(hex) {
    var c = [1, 3, 5].map(function (i) {
      var v = parseInt(hex.slice(i, i + 2), 16) / 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    });
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
  }
  function contrast(x, y) {
    var a = lum(x), b = lum(y);
    return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
  }
  // Text colour on a background: whichever of ink and paper reads better. A fixed
  // "luminance > 0.45" cut-off would put paper text on mid-tones like #ff3b1d (3.4:1)
  // or #ff7a00 (2.6:1). Comparing both contrasts gives >= 4.5:1 for every colour except
  // a narrow mid-tone band (luminance ~0.15-0.22) where neither ink can reach it; the
  // floor there is 4.25:1. css/ct-daily.css therefore puts only LARGE text (3:1) directly
  // on colour a -- all body-size text sits on paper or white.
  function ink(hex) { return contrast(hex, INK) >= contrast(hex, PAPER) ? INK : PAPER; }
  // Text on the black primary button: colour a when it is light (>= 9:1 on #111 at the
  // 0.45 threshold), otherwise paper (>= 17:1).
  function btn(hex) { return lum(hex) > 0.45 ? hex : PAPER; }

  function apply(doc) {
    var look;
    try { look = parseCookie(doc.cookie); } catch (e) { return null; }
    if (!look) return null;
    var el = doc.documentElement, s = el.style;
    s.setProperty('--d-a', look.a);
    s.setProperty('--d-b', look.b);
    s.setProperty('--d-on', ink(look.a));
    s.setProperty('--d-onb', ink(look.b));
    s.setProperty('--d-btn', btn(look.a));
    el.setAttribute('data-look', 'daily');
    return look;
  }

  var api = { parseCookie: parseCookie, lum: lum, contrast: contrast, ink: ink, btn: btn, apply: apply };
  if (typeof module !== 'undefined' && module.exports) { module.exports = api; return; }
  apply(root.document);
})(this);
