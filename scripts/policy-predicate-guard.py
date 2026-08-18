#!/usr/bin/env python3
"""Tor gegen eine Regel, die niemand anwendet (#579).

## Warum

Am 18.08. viermal in einer Nacht dieselbe Form getroffen: etwas ist gebaut,
geprueft und dokumentiert -- und nichts Lebendes ruft es auf.

* **#576** `host_auth_required` beantwortete die Frage korrekt, wurde aber nur
  innerhalb eines fremden Zweigs konsultiert. Ohne `CT_EDGE_ADMIN_TOKEN` blieb
  die Fail-Closed-Vorgabe wirkungslos, und ein Test bewies weiter die Regel.
* **#578** `is_authorized` trug den Kommentar "the authorization gate for
  capability access to a shared tunnel" und hatte null Produktionsaufrufer;
  gegated wurde an drei anderen Stellen mit je eigener Kopie derselben Regel.
* **#560** drei ausgelieferte Kanal-Mechanismen, im Betrieb nie ausgeuebt.
* **#225** `convene_with_policy`, alle 17 Aufrufer in der eigenen Datei.

Und **#248** sagt es schon im Juli woertlich: "real, tested library code, but
never wired into the actual CLI flow". Die Klasse ist also nicht neu, sie wurde
nur jedes Mal von Hand gefunden.

## Was geprueft wird

Praedikate, deren Name sie als Regel ausweist (`*_required`, `*_allowed`,
`*_enabled`, `*_ok`, `*_permitted`, `*_gating`, `is_*`), eingestuft je Treffer
gegen die echten `#[cfg(test)]`-Spannen. Ein Praedikat, dessen einzige Aufrufer
Tests sind, ist genau die obige Form.

## Ausfallrichtung

Gescheitert wird, wenn die Menge **waechst** -- also etwas neu unerreichbar
wird. Eine Grundlinie listet den heutigen Stand mit je einem Grund. Verschwindet
ein Eintrag, ist das kein Fehler (jemand hat ihn angeschlossen), wird aber
gemeldet, damit die Grundlinie nicht verwildert.

Diese Richtung ist bewusst: eine handgepflegte Grundlinie altert, aber sie altert
nur ins Harmlose. Der gefaehrliche Fall -- ein neuer toter Waechter rutscht durch
-- ist der, der scheitert.

Bodenschwelle: findet der Erkenner zu wenige Praedikate, ist er kaputt, und ein
leeres Ergebnis liest sich sonst exakt wie ein sauberes.
"""
import re
import sys
import pathlib
import importlib.util

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent
BASELINE = HERE / "policy-predicates.baseline"

# Untergrenzen. Beide sind Aussagen ueber den ERKENNER, nicht ueber den Code:
# unterschreitet er sie, hat er aufgehoert zu greifen, und sein Schweigen waere
# von einem sauberen Lauf nicht zu unterscheiden.
MIN_PREDICATES = 25
MIN_FILES_WITH_TEST_SPANS = 10

spec = importlib.util.spec_from_file_location("survey", HERE / "reachability-survey.py")
survey = importlib.util.module_from_spec(spec)
spec.loader.exec_module(survey)

DECL = re.compile(
    r'^\s*(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?fn\s+'
    r'([a-z_]*(?:_required|_allowed|_enabled|_ok|_permitted|_gating|is_[a-z_]+))\s*\('
)


def main() -> int:
    root = REPO / "crates"
    files = sorted(root.rglob("*.rs"))
    spanned = sum(1 for p in files if survey.test_spans(p))
    if spanned < MIN_FILES_WITH_TEST_SPANS:
        print(
            f"FEHLER: nur {spanned} Dateien mit #[cfg(test)]-Spannen erkannt "
            f"(erwartet >= {MIN_FILES_WITH_TEST_SPANS}). Die Test-Einstufung greift nicht, "
            "also waere jedes Ergebnis dieses Laufs bedeutungslos.",
            file=sys.stderr,
        )
        return 2

    decls = {}
    for p in files:
        try:
            lines = p.read_text(errors="replace").splitlines()
        except OSError:
            continue
        spans = survey.test_spans(p)
        for i, line in enumerate(lines, 1):
            m = DECL.match(line)
            if not m or any(a <= i <= b for a, b in spans):
                continue
            decls[m.group(1)] = f"{p.relative_to(REPO)}:{i}"

    if len(decls) < MIN_PREDICATES:
        print(
            f"FEHLER: nur {len(decls)} Politik-Praedikate gefunden (erwartet >= "
            f"{MIN_PREDICATES}). Der Erkenner greift nicht mehr -- vermutlich hat sich die "
            "Namensform oder die Signaturschreibweise geaendert.",
            file=sys.stderr,
        )
        return 2

    prod_calls = dict.fromkeys(decls, 0)
    for p in files:
        try:
            lines = p.read_text(errors="replace").splitlines()
        except OSError:
            continue
        spans = survey.test_spans(p)
        for i, line in enumerate(lines, 1):
            if any(a <= i <= b for a, b in spans) or DECL.match(line):
                continue
            for n in decls:
                if re.search(rf'\b{re.escape(n)}\s*\(', line):
                    prod_calls[n] += 1

    unreachable = {n for n, c in prod_calls.items() if c == 0}

    known = {}
    if BASELINE.exists():
        for raw in BASELINE.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            name, _, why = line.partition("#")
            known[name.strip()] = why.strip()

    new = sorted(unreachable - set(known))
    gone = sorted(set(known) - unreachable)

    print(f"Politik-Praedikate: {len(decls)}   ohne Produktionsaufrufer: {len(unreachable)}")
    for n in gone:
        print(f"  ANGESCHLOSSEN (aus der Grundlinie streichen): {n}  -- {known[n]}")
    if not new:
        print("Keine neue Regel ohne Anwender.")
        return 0

    print("", file=sys.stderr)
    print(
        "FEHLER: neue Regel(n) ohne einen einzigen Produktionsaufrufer -- gebaut und "
        "geprueft, aber nichts Lebendes ruft sie (#579):",
        file=sys.stderr,
    )
    for n in new:
        print(f"  {n}  ({decls[n]})", file=sys.stderr)
    print(
        "\nEntweder anschliessen, oder mit einer Begruendung in "
        f"{BASELINE.relative_to(REPO)} eintragen. Ein Test, der die Regel belegt, ist "
        "KEINE Begruendung -- er beweist die Regel, nicht ihre Anwendung.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
