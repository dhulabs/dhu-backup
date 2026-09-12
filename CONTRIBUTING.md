# Contributing

## Running the tests

Both platforms, the same command, the system interpreter:

```bash
/usr/bin/python3 -m unittest discover -s tests -p 'test_*.py'
```

717 tests. Green on macOS under Python 3.9 and on Ubuntu under Python 3.14. Use
`/usr/bin/python3` rather than whatever is first on `PATH`: the daemon runs
under the system interpreter with `-E -s -S`, and a test run under a pyenv or
homebrew Python is not testing the thing that ships.

Compile checks, which CI also runs:

```bash
/usr/bin/python3 -m py_compile src/*.py
bash -n src/install.sh src/uninstall.sh
bash src/install.sh --dry-run --watch demo=/tmp/demo --owner-uid 501
```

The last one changes nothing and must exit 0. Add `--platform linux` to see the
other platform's plan from either machine; that flag is refused without
`--dry-run`, because it changes the install root and the service manager, so a
real run under it would install the wrong platform's daemon.

The suite is platform-aware rather than platform-specific. It asserts *this*
platform's install surface directly and the other platform's through
`--dry-run --platform`. Three tests that assert the scripts refuse to run
without root skip when the suite itself runs as root, because as root they were
not asserting a refusal — they were performing a real install and a real
uninstall.

Regenerate the credential predicate's derived population after changing any
rule in `src/credential_patterns.py`:

```bash
/usr/bin/python3 src/tools/derive-own-fixture.py
```

## The rules this codebase is held to

These are not style preferences. Each one is here because breaking it produced a
defect that shipped, and each is stated as a rule for the next change.

**Protection is structural, never a rule the daemon remembers.** A rule the
agent follows is a rule a mutated guard ignores. If a guarantee can be described
as "the daemon checks that…", ask what happens when someone edits the check. If
it can be described as "the kernel refuses…", it is a property. The recurring
failure in this project's review history was stating this principle and then
building something behavioural: a trigger inside the tree it protected, a user
LaunchAgent whose plist the adversary owns, a watch list read from a row the
adversary writes.

**Every guard is proven as a pure function over fabricated inputs.** The
decision functions live in `src/dhu_backup_core.py` and take plain values —
a stat-like object, a relative path, a limits tuple — and return a verdict. A
test does not need a filesystem, a daemon or a store to assert what a guard
decides. A guarantee that can only be tested by standing up the whole system is
a guarantee that will be tested rarely.

**A destructive sink is never fired to prove its guard.** `prune_plan` returns a
plan; the executor that actually unlinks lives in `dhu-backupd.py` and is never
imported by a test. Proving a delete guard by running the delete means that the
day the guard is wrong, the test suite is the thing that destroys the data.

**A claim and its evidence must share a population.** The worked example: a test
module built its fixtures under a hard-coded scratch directory that existed only
on the machine where it was written, and `setUp` skipped when the directory was
missing. There, 80 tests ran. On a fresh clone, in CI, and on a clean VM, the
directory did not exist, all 80 skipped, and the suite still printed OK. The
claim "the suite passes" and the evidence for it had stopped describing the same
set of tests. A test that needs a scratch directory creates one. If the
environment names a path that does not exist, let it raise: an error is loud and
a skip is not. The same rule governs fixtures — a population derived from a
guard's *tests* is a claim about the tests, not about the guard.

The second worked example cost real data. The store keeps the version
directories of every file in one source directory as siblings, and both
retention plans were keyed on that directory rather than on the file: the
rolling window rolled the only versions of a busy file's siblings, and the age
prune would have kept one version per directory. Every test of both plans used
one file per directory, so every test passed. The population the tests drew
from was not the population the daemon fed the function. When a function is
called on data the daemon builds, at least one test has to build that data the
same way the daemon does — several files in one directory, here — rather than
the simplest shape that satisfies the signature.

**No silent fallbacks. Every status distinguishes reported, missing and
degraded.** "I looked and there is nothing" and "I could not look" are opposite
claims, and code that collapses them abandons work that is sitting on disk.
`dhu_backup_announce` has six statuses and three different exit codes for
exactly this reason. The heartbeat distinguishes `ok`, `degraded`,
`unprotected` and `scan-failed`; an earlier build reported `ok` with a zero file
count for the last two, and the boot banner then said "protecting uncommitted
work" over an empty store. A protection that reports success while protecting
nothing is worse than one that is visibly absent.

Two corollaries that come up often. A store-wide budget going degraded never
self-heals — "prune the oldest to make room" quietly converts a retention
guarantee into a best-effort cache whose only symptom is a file that is not
there when you need it, so the decision type has no such case. And a per-entry
condition must never be able to switch the whole protection off, which is why
three of the five budgets skip one file and only two stop the daemon.

**A root daemon executes only root-owned bytes.** The interpreter, its resolved
symlink target, the daemon source, the config and the install directory are all
root-owned. A user-owned binary executed by root is a root shell for any agent.
The rule is one pure function, `interpreter_verdict`, used by both the installer
before it writes a service file and the daemon at every start, rather than each
spelling it out. Nothing outside the standard library and that root-owned
directory may be imported: a dependency is a file somebody else can replace.

**When you implement someone else's specification, absence is a decision.** Read
the machine-readable schema, not the prose page, and enumerate every optional
field on every object you emit. For each one, either set it or write down why
the default is right — in the source, next to the thing that omits it. Some
defaults are unsafe: the MCP tool hints `destructiveHint` and `openWorldHint`
both default to **true**, so four strictly read-only tools here spent their
first release advertising themselves as possibly destructive and possibly
reaching the internet, by saying nothing at all.

That is the same "no silent fallbacks" rule the daemon is held to, applied one
layer out. It was missed because the rule was only ever aimed at shapes this
project invented — the health verdicts, the announce statuses, the three-way
degraded/warning/ok split were each argued over for hours — while a third-party
protocol was treated as a transport to make work rather than a contract with
semantics of its own. The tests covered behaviour, and the server behaved.

An outside scanner found it in one automated pass, after four rounds of review
here had not. Depth and breadth catch different defects, and neither substitutes
for the other. Cheap external conformance checks are worth running precisely
because they are looking for a different class of thing than the person who
wrote the code.


## Scope

Changes to the daemon's admission guards, the credential predicate, the budgets
or the store layout should say which of the rules above they are exercising, and
what was run to check it. This project's most useful findings came from running
it rather than reading it — a FIFO that hangs the open, a 0444 index that breaks
sqlite, a symlink rule that was dead code because the caller ran realpath first.
Reading found none of those.

## The review numbering in the source

Comments and docstrings cite findings as `C5`, `H2`, `M8`, `I3`, `A2` and
"round 2". Those are the numbered findings of a pre-release adversarial review
that is not published, because it quotes a private codebase. The reasoning
behind each citation is restated where it is cited, so nothing in this
repository depends on reading it; the numbers are kept so the history of a
decision can be traced by the people who hold that document.
