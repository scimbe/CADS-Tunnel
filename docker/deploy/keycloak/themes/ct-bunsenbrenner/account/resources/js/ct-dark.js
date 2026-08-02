// Flip PatternFly's own dark-theme token set on before the account console's
// React app paints, so the stock light theme never flashes. `pf-v5-t-dark`
// is PatternFly's documented theme class (see main-*.css's `.pf-v5-t-dark`
// rule) -- this reuses their own remapped tokens rather than us hand-picking
// colors for every component.
document.documentElement.classList.add("pf-v5-t-dark");
