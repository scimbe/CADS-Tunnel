#!/usr/bin/env bash
# Does the #554 revocation guard actually cover EVERY relay it claims to?
#
# `every_token_carrying_relay_goes_through_the_revocation_guard_554` reads the source and
# asserts that each statement containing a relay-family call also contains `until_revoked`.
# That the test is green proves the sources look right; it does NOT prove the test would
# notice if one of them stopped being wrapped. #566 is why the difference matters: the guard
# was green for months while the QUIC data plane went unguarded, because the guard matched
# call FORMS and that call had a different form and spanned two lines.
#
# So: take each guarded relay site in turn, remove its guard, and require the test to fail.
# A site where the test stays green is a blind spot -- an unwrapped relay there would ship.
#
# The mutation renames `until_revoked` to a same-signature alias rather than deleting it, so
# the crate still compiles and the run is a real test result instead of a build error.
#
# Usage: scripts/probe-554-guard.sh          (from the repo root; needs docker)
set -uo pipefail

SRC=crates/edge/src/serve.rs
BAK=$(mktemp)
cp "$SRC" "$BAK"
restore() { cp "$BAK" "$SRC"; rm -f "$BAK"; }
trap restore EXIT

mutate() { # $1 = zero-based index of the guarded relay site to disarm
python3 - "$1" <<'PY'
import sys, re
k = int(sys.argv[1]); p = 'crates/edge/src/serve.rs'
src = open(p).read()
prod_end = src.find("\n#[cfg(test)]\n")
fams = ("relay(", "framed_relay(", "relay_quic(")
sites = []
for m in re.finditer(r'until_revoked\(', src[:prod_end]):
    a = src.rfind(';', 0, m.start()) + 1
    b = src.find(';', m.end())
    st = ' '.join(src[a:b].split())
    if any((" " + f) in st or ("=" + f) in st or ("= " + f) in st for f in fams):
        sites.append(m.start())
if k >= len(sites):
    sys.exit(2)          # no more sites -- the caller stops here
s = sites[k]
out = src[:s] + 'guarded_probe(' + src[s + len('until_revoked('):]
alias = ('\n#[allow(dead_code)]\nasync fn guarded_probe<T>(state: &EdgeState<Connection>,'
         ' token: &RoutingToken, fut: impl std::future::Future<Output = std::io::Result<T>>)'
         ' -> Result<T, BoxError> { until_revoked(state, token, fut).await }\n')
i = out.find('\n#[cfg(test)]\n')
open(p, 'w').write(out[:i] + alias + out[i:])
PY
}

fails=0
for k in $(seq 0 63); do
  cp "$BAK" "$SRC"
  mutate "$k" || break                     # exit 2 = every site has been probed
  out=$(docker run --rm -v "$PWD":/w -w /w -v cads-tunnel-target:/w/target \
        -v cargo-registry:/usr/local/cargo/registry -e CARGO_INCREMENTAL=0 \
        rust:1-slim-bookworm sh -c 'cargo test -p ct-edge --lib every_token_carrying 2>&1')
  # Three outcomes, not two. A build error is NOT a pass: it means the probe never ran, and
  # counting it as "the guard fired" would be the same mistake this whole family of checks
  # exists against.
  if printf '%s' "$out" | grep -q '^error\[E'; then
    echo "site $k: DID NOT BUILD -- probe inconclusive, fix the probe before trusting it"
    fails=$((fails + 1))
  elif printf '%s' "$out" | grep -q 'revocation_guard_554 ... FAILED'; then
    echo "site $k: guard reports it, as it must"
  else
    echo "site $k: *** SILENT *** -- an unwrapped relay here would ship"
    fails=$((fails + 1))
  fi
done

# Match on the test's own line, not on a count of lines containing FAILED: cargo prints both
# `test <name> ... FAILED` and `test result: FAILED`, so a `== 1` check is wrong for every
# site at once. The first run of this probe reported 12 blind spots that way -- a false alarm
# that only looked wrong because 12-out-of-12 is implausible.
[ "$fails" -eq 0 ] && echo "every guarded relay site is covered." || echo "$fails site(s) need attention."
exit $((fails > 0))
