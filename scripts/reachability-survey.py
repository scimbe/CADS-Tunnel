#!/usr/bin/env python3
"""Which public items of a crate are reachable from production code — across repositories.

Written after two surveys in this project reached the WRONG conclusion with a plain grep:

  * #476 called `ct_common::mcp` dead. Its production caller is in ct-agent, a different
    repository, so a grep confined to this workspace found nothing and was believed.
  * A flat "has a non-test caller" count then called `a2a_send`/`a2a_recv` live. Their only
    callers were other members of the same dead cluster, which a flat count cannot see.

So this tool does the two things those greps did not: it searches every consumer given to it,
and it iterates to a fixpoint so a caller only counts once it is itself reachable.

Classification is per hit against the file's real `#[cfg(test)]` spans, because inline test
modules exist in production files — "not in tests.rs" is not the same as "not a test".

Usage:
  scripts/reachability-survey.py <crate-src-dir> <consumer-dir> [<consumer-dir> ...]

It prints how many files each consumer contributed. A survey that silently searched nothing
otherwise reports exactly what a survey that found nothing reports.
"""
import os, re, sys

def test_only_files(roots):
    """Files that are ENTIRELY test code although nothing inside them says so.

    `#[cfg(test)] mod tests;` puts the attribute in the PARENT file; `tests.rs` itself carries
    no marker, so a span scan of it finds nothing and reads it as production. ct-agent's
    `channel_run/tests.rs` is 2000+ lines that way, and its test functions turned up as
    "production callers" of the very functions being surveyed.
    """
    decl = re.compile(r'#\[cfg\(test\)\]\s*(pub\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;')
    out = set()
    for root in roots:
        for dp, _, fs in os.walk(root):
            if '/target/' in dp:
                continue
            for f in fs:
                if not f.endswith('.rs'):
                    continue
                p = os.path.join(dp, f)
                txt = open(p, encoding='utf8', errors='replace').read()
                for m in decl.finditer(txt.replace('\n', ' ')):
                    name = m.group(2)
                    for cand in (os.path.join(dp, name + '.rs'), os.path.join(dp, name, 'mod.rs')):
                        if os.path.exists(cand):
                            out.add(os.path.abspath(cand))
    return out


def test_spans(path):
    lines = open(path, encoding='utf8', errors='replace').read().split('\n')
    spans, i = [], 0
    while i < len(lines):
        if '#[cfg(test)]' in lines[i]:
            j, depth, started = i, 0, False
            while j < len(lines):
                depth += lines[j].count('{') - lines[j].count('}')
                if '{' in lines[j]:
                    started = True
                if started and depth <= 0:
                    break
                j += 1
            spans.append((i + 1, j + 1))
            i = j
        i += 1
    return spans

FN_DEF = re.compile(r'^\s*(pub(\([a-z]+\))?\s+)?(async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)')
# An identifier immediately followed by `(` or a turbofish — i.e. a call, not a mention.
CALL = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:::<[^>]*>)?\s*\(')

def enclosing_fn(lines, n):
    """Nearest preceding function definition — the caller, for the transitive step."""
    for k in range(n - 1, -1, -1):
        m = FN_DEF.match(lines[k])
        if m:
            return m.group(4)
    return None

def open_all(root):
    """Every .rs source under `root`, concatenated -- for attribute scans."""
    out = []
    for dp, _, fs in os.walk(root):
        for f in fs:
            if f.endswith('.rs'):
                out.append(open(os.path.join(dp, f), encoding='utf8', errors='replace').read())
    return '\n'.join(out)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    crate_src, consumers = sys.argv[1], sys.argv[2:]

    files = []
    for root in consumers:
        if not os.path.isdir(root):
            print(f"!! path does not exist, nothing searched there: {root}", file=sys.stderr)
            continue
        n = 0
        for dp, _, fs in os.walk(root):
            if '/target/' in dp or '/.claude/' in dp:
                continue
            for f in fs:
                if f.endswith('.rs'):
                    files.append(os.path.join(dp, f))
                    n += 1
        print(f"[searched] {root}: {n} files", file=sys.stderr)
    if not files:
        print("!! nothing was searched — refusing to report a result", file=sys.stderr)
        return 2

    # Public items of the crate under survey.
    own = {}
    for dp, _, fs in os.walk(crate_src):
        for f in fs:
            if not f.endswith('.rs'):
                continue
            p = os.path.join(dp, f)
            impl_depth, depth = None, 0
            for i, line in enumerate(open(p, encoding='utf8', errors='replace'), 1):
                if re.match(r'^\s*(unsafe\s+)?impl\b', line) and impl_depth is None:
                    impl_depth = depth
                before = depth
                depth += line.count('{') - line.count('}')
                if impl_depth is not None and depth <= impl_depth and before > impl_depth:
                    impl_depth = None
                # EVERY function, not just the public ones. The transitive step needs the
                # private hops: `run_upgradable_session` (pub) reaches `noise_pump_multiplexed`
                # only through a private `..._inner`, and a chain that stops at the first
                # private function reported that pump as dead — it is not, it carries the live
                # upgrade path. Publicness is a reporting filter, applied at the end.
                m = FN_DEF.match(line)
                if m:
                    is_pub = bool(m.group(1)) and 'pub(' not in (m.group(1) or '')
                    own[m.group(4)] = (f"{os.path.relpath(p, crate_src)}:{i}", is_pub,
                                       impl_depth is not None)

    # (symbol, calling file, calling function) for every non-test call site.
    own_names = set(own)
    whole_file_tests = test_only_files(consumers + [crate_src])
    if whole_file_tests:
        print(f"[test-only files] {len(whole_file_tests)} (declared `#[cfg(test)] mod X;` "
              f"in a parent, no marker inside)", file=sys.stderr)
    cache = {}
    for p in files:
        if os.path.abspath(p) in whole_file_tests:
            continue
        lines = open(p, encoding='utf8', errors='replace').read().split('\n')
        spans = test_spans(p)
        inside_crate = os.path.abspath(p).startswith(os.path.abspath(crate_src))
        for n, line in enumerate(lines, 1):
            s = line.strip()
            if s.startswith('//') or s.startswith('///') or s.startswith('*'):
                continue
            if any(a <= n <= b for a, b in spans):
                continue
            # Pull the called identifiers out of the line ONCE and intersect with the
            # crate's functions. Testing every symbol against every line is quadratic and
            # does not finish on a workspace this size.
            for sym in set(CALL.findall(line)) & own_names:
                if FN_DEF.match(line) and FN_DEF.match(line).group(4) == sym:
                    continue
                cache.setdefault(sym, []).append(
                    (inside_crate, enclosing_fn(lines, n), f"{os.path.relpath(p)}:{n}"))

    # Fixpoint: a symbol is live if called from outside the crate, or from a live symbol.
    # A binary's root is its own `main`, not an outside caller. Without this, everything a
    # binary does looks unreachable: ct-agent's `run_agent`, `run_channel_command` and
    # `rotate_origin_key` were all reported dead, each "only from main".
    live = {s for s, hits in cache.items() if any(not inside for inside, _, _ in hits)}
    live |= {'main'} & set(own)
    changed = True
    while changed:
        changed = False
        for s, hits in cache.items():
            if s in live:
                continue
            if any(inside and fn in live for inside, fn, _ in hits):
                live.add(s)
                changed = True

    # Methods in `impl` blocks are excluded from the verdict, not silently dropped: they are
    # reached through trait dispatch, `derive`d code and generic bounds, none of which appear
    # as a call by name. Reporting them as unreachable would be a false claim -- `serialize`
    # and `deserialize` came out "dead" that way, and serde calls them on every message.
    methods = sorted(s for s, (_, is_pub, in_impl) in own.items() if is_pub and in_impl)
    # Second undecidable class, found the same way as the first -- by checking a name the tool
    # had called dead: `serialize`/`deserialize` in a `card_hex::b32`-style helper module are
    # reached through `#[serde(with = "...")]`, a STRING in an attribute. Nothing calls them by
    # name, and serde calls them on every message that carries a hex field.
    serde_helpers = set()
    if re.search(r'(serde\(with|serialize_with|deserialize_with)\s*=', open_all(crate_src)):
        serde_helpers = {'serialize', 'deserialize'}
    pubs = {s for s, (_, is_pub, in_impl) in own.items()
            if is_pub and not in_impl and s not in serde_helpers}
    dead = sorted(pubs - live)
    print(f"\npublic fns: {len(pubs)} (of {len(own)} total)   reachable: {len(pubs & live)}   "
          f"NOT reachable: {len(dead)}\n")
    for s in dead:
        callers = cache.get(s, [])
        why = "no caller at all" if not callers else \
              "only from " + ", ".join(sorted({fn or '?' for _, fn, _ in callers}))
        print(f"  {s:42s} {own[s][0]:34s} {why}")
    print(f"\nnot decidable by this method: {len(methods)} public methods in impl blocks "
          f"(trait dispatch and derived code call these without naming them)"
          + (f", plus {sorted(serde_helpers)} (reached through #[serde(with = \"...\")])"
             if serde_helpers else "") + ".")
    print("Each remaining name is a STARTING POINT for a per-item decision, not a verdict: "
          "this method cannot see macro-generated calls, trait dispatch, or any consumer "
          "that was not passed in.")
    return 0

if __name__ == '__main__':
    sys.exit(main())
