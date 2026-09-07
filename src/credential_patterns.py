"""The credential predicate's ONE source of truth — data, not logic.

`dhu_backup_core.is_credential_path` is built from this table. Nothing here
decides anything: the file is a list of `Rule`s plus a compile step that turns
each rule's regex source into a compiled pattern and buckets the rules by the
part of the path they are matched against. The matching itself lives in
`dhu_backup_core`, which is where every other decision function lives and where
the tests already look for one.

WHY THIS FILE EXISTS. The patterns were originally transcribed into
`dhu_backup_core.py` from two read guards that an agent runtime already enforced
— one basename-and-segment matcher, one sandbox profile of full-path regexes —
and the only evidence that the transcription was complete was a fixture that
could be regenerated only inside that other codebase. A predicate whose proof
lives in another repository is a predicate this project cannot maintain. So the
patterns moved here, each one carrying its own rationale and its own worked
examples, and `src/tools/derive-own-fixture.py` expands THESE regexes into a
probe population with no other repo involved. The contract inherited from those
two guards was a UNION: refuse everything either one refuses, admit only what
both admit.

THE FAIL DIRECTION IS NOT SYMMETRIC. A work file wrongly sent to `vault/` costs
the operator one `sudo` to recover. A credential file wrongly admitted to
`store/` is agent-readable forever, which is exactly the laundering that review
C4 found. So a rule that is too broad is a nuisance and a rule that is too narrow
is the defect.

THE FIVE KINDS

  ``dir-segment``            a path SEGMENT that makes the whole subtree
                             credential-bearing (`.ssh`, `.aws`, ...).
  ``config-dir``             a vendor directory under `~/.config` whose contents
                             are live credentials (`gh`, `gcloud`, ...).
  ``path-tail``              a specific `<parent>/<name>` pair (`.git/config`).
  ``basename-regex``         key material, matched on the basename and NEVER
                             excused by a template suffix — a private key does
                             not become safe because someone appended
                             `.example` to it.
  ``template-suffix-exempt`` a basename regex that IS excused by a template
                             suffix: `.env` is a secret, `.env.example` is a
                             committed template and the repo is full of them.

TWO FIELDS THE BRIEF DID NOT NAME, AND WHY THEY ARE HERE

  ``where``   which part of the path the pattern is matched against. Only
              ``dir-segment`` has two values, and the difference is load-bearing:
              `.ssh` must fire on the LAST segment too (a file literally named
              `.ssh` is credential material to the guards this was ported from),
              while the `.env` directory rule must fire on NON-FINAL segments
              only — as a basename, `.env.example` is an admitted template. In
              `dhu_backup_core.py` this distinction was a positional index into
              another list (`_TEMPLATABLE_SECRET_PATTERNS[0]`) under a ten-line
              comment. It is data, so it is written down as data.
  ``examples`` carries the verdict it claims, because a test asserts it. An
              example that says only "this path" cannot be checked against
              anything.

Every rule states at least two examples it must REFUSE and at least one it must
ADMIT. The admit example is not decoration: without it, "refuse everything"
satisfies every other test in the suite.

EVERY PATTERN IS A REGEX SOURCE, including the ones that are plainly literals
(`^\\.ssh$`). One representation means the derivation tool has one expander, and
an expander that handles every pattern is an expander that cannot silently skip
one. Case-insensitivity is written inline as a leading `(?i)` for the same
reason — a `flags` field would be a second representation the tool would have to
know about.
"""

import re
from collections import namedtuple

# ── the shape ────────────────────────────────────────────────────────────────

REFUSE = "refuse"
ADMIT = "admit"

Example = namedtuple("Example", "relpath verdict")

#: ``regex`` and ``id`` are computed by `_rule`; everything else is written by
#: hand in the table below.
Rule = namedtuple("Rule", "kind where pattern rationale examples regex id")

KINDS = (
    "dir-segment",
    "config-dir",
    "path-tail",
    "basename-regex",
    "template-suffix-exempt",
)

WHERES = (
    "any-segment",        # every segment, the basename included
    "non-final-segment",  # directory segments only
    "config-child",       # a segment whose parent is `.config`
    "last-two",           # "<parent>/<name>"
    "basename",           # the last segment
)


def _rule(kind, where, pattern, rationale, refuse, admit):
    """The whole compile step: compile the regex, freeze the examples, name it.

    The id is `<kind>|<pattern>` rather than an index, so adding a rule does not
    renumber every row of the derived fixture. `(kind, pattern)` is unique: the
    one pattern that appears twice (`^\\.env($|\\.)`) appears under two kinds,
    which is precisely the distinction that matters.
    """
    examples = tuple(
        [Example(p, REFUSE) for p in refuse] + [Example(p, ADMIT) for p in admit]
    )
    return Rule(kind, where, pattern, rationale, examples,
                re.compile(pattern), "%s|%s" % (kind, pattern))


# ── the template suffix ──────────────────────────────────────────────────────
#
# Not a Rule: it refuses nothing. It is the exemption that `template-suffix-
# exempt` rules are read against, and it is also stripped before the
# `basename-regex` rules run, so `id_rsa.example` is still key material.
TEMPLATE_SUFFIX_PATTERN = r"(?i)\.(example|sample|template|defaults|dist)$"
TEMPLATE_SUFFIX = re.compile(TEMPLATE_SUFFIX_PATTERN)


# ── the rules ────────────────────────────────────────────────────────────────

RULES = (
    # ── directory segments: the whole subtree is credential-bearing ──────────
    _rule("dir-segment", "any-segment", r"^\.ssh$",
          "OpenSSH keeps private keys, authorized_keys and known_hosts here; "
          "the directory is credential material as a whole.",
          refuse=[".ssh/id_ed25519", "home/you/.ssh/config"],
          admit=["docs/ssh-setup.md"]),
    _rule("dir-segment", "any-segment", r"^\.gnupg$",
          "GnuPG's secret keyring and trust database.",
          refuse=[".gnupg/secring.gpg", "home/.gnupg/private-keys-v1.d/key.asc"],
          admit=["docs/gnupg-notes.md"]),
    _rule("dir-segment", "any-segment", r"^\.aws$",
          "The AWS CLI's long-lived access keys and session tokens.",
          refuse=[".aws/credentials", "a/b/.aws"],
          admit=["infra/aws/main.tf"]),
    _rule("dir-segment", "any-segment", r"^\.kube$",
          "A kubeconfig embeds cluster tokens and client certificates inline.",
          refuse=[".kube/config", "a/b/.kube/cache/discovery.json"],
          admit=["infra/kube/deployment.yaml"]),
    _rule("dir-segment", "any-segment", r"^Keychains$",
          "macOS keychain databases — every stored password on the machine.",
          refuse=["Library/Keychains/login.keychain-db", "Keychains/System.keychain"],
          admit=["docs/Keychains-explained.md"]),

    # `.env` as a DIRECTORY. The sandbox profile's rule is /\.env($|\.|/) over the whole
    # path; the basename-only guard admitted `<repo>/.env/creds`, and the adversarial
    # review put that shape in a live store. Non-final only, deliberately: as a
    # BASENAME `.env.example` is a committed template, and the profile's carve-out
    # is `$`-anchored on the whole path, so it excuses the file and not the
    # contents of a directory called `.env.example`.
    _rule("dir-segment", "non-final-segment", r"^\.env($|\.)",
          "`.env` used as a directory name: everything inside it is environment "
          "secrets, whatever the file is called.",
          refuse=[".env/creds", "a/b/.env/inner.txt"],
          admit=[".env.local.example"]),

    # ── ~/.config/<vendor>/ — at ANY depth ───────────────────────────────────
    # The TS guard looked at the immediate parent only, so gcloud's real layout
    # (.config/gcloud/legacy_credentials/<acct>/adc.json) was stored.
    _rule("config-dir", "config-child", r"^gws$",
          "Google Workspace CLI credential store.",
          refuse=[".config/gws/token.json", ".config/gws/deep/nested/creds"],
          admit=["dotfiles/gws/README.md"]),
    _rule("config-dir", "config-child", r"^gh$",
          "GitHub CLI OAuth tokens.",
          refuse=[".config/gh/hosts.yml", ".config/gh/deep/nested/creds"],
          admit=["dotfiles/gh/README.md"]),
    _rule("config-dir", "config-child", r"^gcloud$",
          "gcloud's application-default credentials and access-token databases.",
          refuse=[".config/gcloud/credentials.db",
                  ".config/gcloud/legacy_credentials/you/adc.json"],
          admit=["dotfiles/gcloud/README.md"]),
    _rule("config-dir", "config-child", r"^stripe$",
          "Stripe CLI live API keys.",
          refuse=[".config/stripe/config.toml", ".config/stripe/deep/nested/creds"],
          admit=["dotfiles/stripe/README.md"]),
    _rule("config-dir", "config-child", r"^op$",
          "1Password CLI session state.",
          refuse=[".config/op/config", ".config/op/deep/nested/creds"],
          admit=["dotfiles/op/README.md"]),
    _rule("config-dir", "config-child", r"^doctl$",
          "DigitalOcean CLI API token.",
          refuse=[".config/doctl/config.yaml", ".config/doctl/deep/nested/creds"],
          admit=["dotfiles/doctl/README.md"]),
    _rule("config-dir", "config-child", r"^fly$",
          "Fly.io CLI auth token.",
          refuse=[".config/fly/config.yml", ".config/fly/deep/nested/creds"],
          admit=["dotfiles/fly/README.md"]),

    # ── <parent>/<name> pairs ────────────────────────────────────────────────
    # Evaluated BEFORE the basename rules. Under the original order
    # `.git/credentials` was unreachable — `^credentials$` claimed it first — so
    # the tail rule was dead code that no test could distinguish from a live
    # one. The verdict is identical either way; only the reason changes.
    _rule("path-tail", "last-two", r"^\.docker/config\.json$",
          "Docker registry auth: base64 registry credentials, not settings.",
          refuse=[".docker/config.json", "home/.docker/config.json"],
          admit=[".docker/daemon.json"]),
    _rule("path-tail", "last-two", r"^\.git/config$",
          "A git remote URL can embed a username and a personal access token.",
          refuse=[".git/config", "repo/.git/config"],
          admit=[".git/HEAD"]),
    _rule("path-tail", "last-two", r"^\.git/credentials$",
          "git's plaintext credential store.",
          refuse=[".git/credentials", "repo/.git/credentials"],
          admit=[".git/description"]),
    _rule("path-tail", "last-two", r"^gh/hosts\.yml$",
          "GitHub CLI host tokens, reached by a path that is not under .config.",
          refuse=["gh/hosts.yml", "backup/gh/hosts.yml"],
          admit=["gh/README.md"]),
    _rule("path-tail", "last-two", r"^gcloud/credentials\.db$",
          "gcloud's credential database, outside ~/.config.",
          refuse=["gcloud/credentials.db", "backup/gcloud/credentials.db"],
          admit=["gcloud/README.md"]),
    _rule("path-tail", "last-two", r"^gcloud/access_tokens\.db$",
          "gcloud's cached OAuth access tokens, outside ~/.config.",
          refuse=["gcloud/access_tokens.db", "backup/gcloud/access_tokens.db"],
          admit=["gcloud/config_default"]),
    _rule("path-tail", "last-two", r"^JetBrains/consentOptions$",
          "JetBrains IDE account state.",
          refuse=["JetBrains/consentOptions", "Library/Preferences/JetBrains/consentOptions"],
          admit=["JetBrains/options.xml"]),
    _rule("path-tail", "last-two", r"^\.claude/\.credentials\.json$",
          "Claude Code's stored OAuth credentials.",
          refuse=[".claude/.credentials.json", "home/.claude/.credentials.json"],
          admit=[".claude/settings.json"]),

    # ── key material: never excused by a template suffix ─────────────────────
    _rule("basename-regex", "basename", r"^\.netrc$",
          "netrc holds cleartext machine logins and passwords.",
          refuse=[".netrc", "home/.netrc"],
          admit=["docs/netrc-howto.md"]),
    _rule("basename-regex", "basename", r"^\.pgpass$",
          "libpq's password file.",
          refuse=[".pgpass", "home/.pgpass"],
          admit=["docs/pgpass.md"]),
    _rule("basename-regex", "basename", r"^\.htpasswd$",
          "Apache password hashes, offline-crackable.",
          refuse=[".htpasswd", "www/.htpasswd"],
          admit=["www/.htaccess"]),
    _rule("basename-regex", "basename", r"^\.git-credentials$",
          "git's plaintext credential store, by basename at any depth.",
          refuse=[".git-credentials", "home/.git-credentials"],
          admit=["docs/git-credentials.md"]),
    _rule("basename-regex", "basename", r"^credentials$",
          "A bare file called `credentials` — the AWS CLI's and many others'.",
          refuse=["credentials", "backup/credentials"],
          admit=["credentials.md"]),
    _rule("basename-regex", "basename", r"^id_(rsa|dsa|ecdsa|ed25519)$",
          "An SSH private key, wherever it has been copied to.",
          refuse=["deploy/keys/id_rsa", "id_ed25519"],
          admit=["docs/id_rsa-rotation.md"]),
    _rule("basename-regex", "basename", r"(?i)\.(pem|key|p12|pfx|keystore|jks)$",
          "Private-key and keystore file extensions, case-insensitively.",
          refuse=["certs/server.pem", "android/release.jks"],
          admit=["docs/pem-format.md"]),
    _rule("basename-regex", "basename", r"^\.claude\.json$",
          "Claude Code's user state file, which has held OAuth material.",
          refuse=[".claude.json", "home/.claude.json"],
          admit=["claude-config.json"]),
    _rule("basename-regex", "basename", r"^\.pypirc$",
          "PyPI upload tokens for `twine`/`pip` publishing.",
          refuse=[".pypirc", "home/.pypirc"],
          admit=["docs/pypirc.md"]),
    _rule("basename-regex", "basename", r"^\.?[a-z]*_history$",
          "Shell history: secrets typed on a command line end up here verbatim.",
          refuse=[".zsh_history", "home/bash_history"],
          admit=["docs/history.md"]),
    _rule("basename-regex", "basename", r"\.(keychain|keychain-db)$",
          "A macOS keychain file copied out of Library/Keychains.",
          refuse=["backup/login.keychain-db", "backup/login.keychain"],
          admit=["docs/keychain-notes.md"]),

    # ── secrets that a template suffix DOES excuse ───────────────────────────
    # Committed `.env.example` files are everywhere and hold no secrets; vaulting
    # them would make the mirror useless for the files most likely to be needed.
    _rule("template-suffix-exempt", "basename", r"^\.env($|\.)",
          "Environment secrets, unless the basename ends in a template suffix.",
          refuse=[".env", "app/.env.production"],
          admit=[".env.example"]),
    _rule("template-suffix-exempt", "basename", r"^\.npmrc$",
          "npm registry auth tokens, unless the basename is a template.",
          refuse=[".npmrc", "packages/x/.npmrc"],
          admit=[".npmrc.example"]),
    _rule("template-suffix-exempt", "basename", r"^\.yarnrc$",
          "Yarn 1 registry auth tokens, unless the basename is a template.",
          refuse=[".yarnrc", "packages/x/.yarnrc"],
          admit=[".yarnrc.example"]),
    _rule("template-suffix-exempt", "basename", r"^\.yarnrc\.yml$",
          "Yarn Berry npmAuthToken entries, unless the basename is a template.",
          refuse=[".yarnrc.yml", "packages/x/.yarnrc.yml"],
          admit=[".yarnrc.yml.example"]),
)


# ── the compile step's other half: bucket by match site ──────────────────────
#
# The matcher in `dhu_backup_core` reads these tuples in order. Bucketing here
# rather than filtering there keeps the per-file cost to the rules that can
# possibly apply, and keeps the matcher a straight read of this table.

def _bucket(kind, where=None):
    return tuple(r for r in RULES
                 if r.kind == kind and (where is None or r.where == where))


DIR_SEGMENT_ANY = _bucket("dir-segment", "any-segment")
DIR_SEGMENT_NON_FINAL = _bucket("dir-segment", "non-final-segment")
CONFIG_DIR = _bucket("config-dir")
PATH_TAIL = _bucket("path-tail")
KEY_MATERIAL = _bucket("basename-regex")
TEMPLATABLE = _bucket("template-suffix-exempt")

#: The reason string a fired rule produces, by (kind, where). Kept identical to
#: the strings the hand-written predicate produced, so the daemon's log, the
#: helper's `vaulted` answer and the announcement all read exactly as before.
REASON_TEMPLATES = {
    ("dir-segment", "any-segment"): "%s/ holds credential material",
    ("dir-segment", "non-final-segment"): "%s/ is a credential directory",
    ("config-dir", "config-child"): "~/.config/%s/ holds live credentials",
    ("path-tail", "last-two"): '"%s" holds credential material',
    ("basename-regex", "basename"): '"%s" is key material',
    ("template-suffix-exempt", "basename"): '"%s" matches a secret-file pattern',
}


def rule_by_id(rule_id):
    """The rule with this id, or None. Used by the fixture tests and the tool."""
    for rule in RULES:
        if rule.id == rule_id:
            return rule
    return None
