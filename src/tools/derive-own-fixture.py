#!/usr/bin/python3
"""Derive tests/credential_fixture_own.json from THIS repo's own rules.

    /usr/bin/python3 src/tools/derive-own-fixture.py            # write
    /usr/bin/python3 src/tools/derive-own-fixture.py --check    # fail if stale

WHY IT EXISTS. The other fixture in tests/ was derived from the read guards of
the project this tool was extracted from, and regenerating it needs that
checkout. That fixture is a floor and stays frozen. This one is the population
dhu-backup can regenerate on any machine, from `src/credential_patterns.py`
alone, so the predicate has a proof it owns.

WHAT A DERIVED POPULATION BUYS. The first version of the older fixture was built
from the guards' TEST LITERALS. That population exercised about a third of the
rules, and twelve mutations of real patterns left the suite green. A fixture
derived from tests is a claim about the tests; only one derived from the
PATTERNS is a claim about the patterns. So every probe here comes from a rule's
own regex, expanded, or from the examples that rule states about itself — and
every row records WHICH RULE it was generated from, so a rule that never fires
on its own probes is detectable rather than invisible.

THE EXPANDER THROWS. It handles exactly the constructs these patterns use and
raises on anything else. A silent "I could not expand that" would quietly shrink
the population back to whatever happened to be expressible, which is the defect
this file exists to prevent. If a new pattern uses a construct that is not here,
teach the expander — do not let it skip.
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
SRC = os.path.join(REPO_ROOT, "src")
sys.path.insert(0, SRC)

import credential_patterns  # noqa: E402
import dhu_backup_core  # noqa: E402

OUT_PATH = os.path.join(REPO_ROOT, "tests", "credential_fixture_own.json")

#: One representative member per character class the rules actually use.
#: Guessing a member for an unlisted class would emit a probe that does NOT
#: match the pattern it came from; the row would be filed as an admitted path
#: and that rule would silently go unexercised.
CLASS_SAMPLES = {"a-z": "zsh"}


class Expander(object):
    """Expand a regex source into every concrete string it can match.

    A direct port of the expander the frozen derivation used, with the same
    discipline: literals, escapes, `(a|b)` alternation, `?`, `[a-z]*`, anchors,
    and a raise on anything else.
    """

    def __init__(self, source):
        self.source = source
        self.i = 0

    def branch(self, stop_at_paren):
        source = self.source
        out = [""]
        alternatives = []
        while self.i < len(source):
            char = source[self.i]
            if char == ")" and stop_at_paren:
                self.i += 1
                alternatives.extend(out)
                return alternatives
            if char == "|":
                self.i += 1
                alternatives.extend(out)
                out = [""]
                continue
            if char in "^$":
                self.i += 1
                continue
            if char == "\\":
                literal = source[self.i + 1]
                self.i += 2
                if self.i < len(source) and source[self.i] == "?":
                    self.i += 1
                    out = [p + q for p in out for q in ("", literal)]
                else:
                    out = [p + literal for p in out]
                continue
            if char == "(":
                self.i += 1
                inner = self.branch(True)
                if self.i < len(source) and source[self.i] == "?":
                    self.i += 1
                    out = [p + q for p in out for q in [""] + inner]
                else:
                    out = [p + q for p in out for q in inner]
                continue
            if char == "[":
                close = source.find("]", self.i)
                if close < 0:
                    raise ValueError("unterminated character class in %r" % source)
                name = source[self.i + 1:close]
                self.i = close + 1
                star = self.i < len(source) and source[self.i] == "*"
                plus = self.i < len(source) and source[self.i] == "+"
                if star or plus:
                    self.i += 1
                if name not in CLASS_SAMPLES:
                    raise ValueError("unmodelled character class [%s] in %r" % (name, source))
                # `*` means "or nothing"; `+` requires at least one. Modelling
                # them identically would emit a probe that cannot match a `+`.
                pieces = ["", CLASS_SAMPLES[name]] if star else [CLASS_SAMPLES[name]]
                out = [p + q for p in out for q in pieces]
                continue
            if char in "*+?.":
                raise ValueError("unsupported quantifier %r in %r" % (char, source))
            self.i += 1
            out = [p + char for p in out]
        alternatives.extend(out)
        return alternatives


def expand(pattern):
    """Every concrete string `pattern` can match, in a stable order."""
    source = pattern
    # The only inline flag these rules use. Stripped EXPLICITLY rather than by a
    # catch-all: an unrecognised `(?...)` group must still reach the raise.
    if source.startswith("(?i)"):
        source = source[4:]
    expander = Expander(source)
    values = expander.branch(False)
    if expander.i < len(expander.source):
        raise ValueError("trailing input in %r" % pattern)
    ordered = []
    for value in values:
        if value and value not in ordered:
            ordered.append(value)
    if not ordered:
        raise ValueError("%r expanded to nothing" % pattern)
    return ordered


def probes_for(rule):
    """`[(relpath, source, expected)]` — every probe this rule is responsible for.

    `expected` is the verdict the rule CLAIMS for its own examples, and None for
    an expanded probe, where the verdict is an observation rather than a claim.
    """
    rows = []
    seen = set()

    def add(relpath, source, expected):
        if relpath in seen:
            return
        seen.add(relpath)
        rows.append((relpath, source, expected))

    for value in expand(rule.pattern):
        # The four shapes the frozen derivation used: bare, nested, as a
        # DIRECTORY holding a file, and under `.config` — the last because
        # `~/.config/<vendor>/` is the shape a basename-only guard misses.
        add(value, "expanded", None)
        add("a/b/%s" % value, "expanded", None)
        add("%s/inner.txt" % value, "expanded", None)
        add(".config/%s/token.json" % value, "expanded", None)
    for example in rule.examples:
        add(example.relpath, "example", example.verdict)
    return rows


def build():
    rows = []
    for rule in credential_patterns.RULES:
        for relpath, source, expected in probes_for(rule):
            match = dhu_backup_core.credential_match(relpath)
            rows.append({
                "rule": rule.id,
                "kind": rule.kind,
                "where": rule.where,
                "relpath": relpath,
                "source": source,
                "expected": expected,
                "refused": match is not None,
                "reason": match.reason if match is not None else None,
                "fired": match.rule.id if match is not None else None,
            })
    return {
        "generated_by": "src/tools/derive-own-fixture.py",
        "source_of_truth": "src/credential_patterns.py",
        "contract": (
            "Every row's `refused`/`fired` is what dhu_backup_core.credential_match "
            "answers for `relpath`. Every rule must appear as `fired` on at least "
            "one row it generated, and every row whose `source` is `example` must "
            "match the verdict its rule claims in `expected`."
        ),
        "rule_count": len(credential_patterns.RULES),
        "row_count": len(rows),
        "refused_count": sum(1 for r in rows if r["refused"]),
        "rows": rows,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(prog="derive-own-fixture")
    parser.add_argument("--check", action="store_true",
                        help="exit 1 if the committed fixture is not what this "
                             "run would write, and change nothing")
    args = parser.parse_args(argv)

    payload = json.dumps(build(), indent=2, sort_keys=False) + "\n"
    if args.check:
        try:
            with open(OUT_PATH) as handle:
                current = handle.read()
        except IOError as exc:
            sys.stderr.write("cannot read %s: %s\n" % (OUT_PATH, exc))
            return 1
        if current != payload:
            sys.stderr.write(
                "%s is STALE — rerun src/tools/derive-own-fixture.py\n" % OUT_PATH)
            return 1
        sys.stdout.write("%s is current (%d rows)\n"
                         % (OUT_PATH, payload.count('"relpath"')))
        return 0
    with open(OUT_PATH, "w") as handle:
        handle.write(payload)
    data = json.loads(payload)
    sys.stdout.write("wrote %s — %d rules, %d rows, %d refused\n"
                     % (OUT_PATH, data["rule_count"], data["row_count"],
                        data["refused_count"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
