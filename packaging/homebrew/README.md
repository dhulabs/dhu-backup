# Homebrew packaging

`dhu-backup.rb` is a formula for a tap. **It is not published yet**, and no tap
repository exists: `brew install dhulabs/tap/dhu-backup` will fail until the
steps below have been carried out. Nothing in this directory is on the trust
path of an installed daemon.

## What the formula installs, and what it refuses to

It installs the source tree into `libexec` and a `dhu-backup` wrapper into
`bin`, so `dhu-backup status` works straight after `brew install` and reports,
correctly, that nothing is capturing yet.

It **does not install, register, start or touch the daemon**, and that is the
point rather than an omission. `brew` runs as the user — the same principal a
coding agent runs as — and the guarantee this product makes is that the mirror
is written by a second principal the user's own processes cannot stop, kill or
write to. A formula that could stand that daemon up would be a path from an
agent-writable package manager to root. The daemon is one deliberate `sudo`, by
a human who has read `install.sh`, and the formula's `caveats` prints that exact
command.

The formula also declares no `python` dependency. The daemon and the helpers run
under `/usr/bin/python3` with `-E -s -S`, because a root daemon must execute only
root-owned bytes and a Homebrew python lives where the user can write.

## Creating the tap

A tap is an ordinary GitHub repository named `homebrew-<name>`:

```bash
# once
gh repo create dhulabs/homebrew-tap --public
git clone https://github.com/dhulabs/homebrew-tap.git
mkdir -p homebrew-tap/Formula
cp packaging/homebrew/dhu-backup.rb homebrew-tap/Formula/
```

Then, from a clone of the tap:

```bash
git -C homebrew-tap add Formula/dhu-backup.rb
git -C homebrew-tap commit -m "dhu-backup 0.3.0"
git -C homebrew-tap push
```

Users then run:

```bash
brew tap dhulabs/tap
brew install dhu-backup
```

## Filling in the sha256

The formula ships with a clearly-marked placeholder rather than a guess. Compute
it from the **published** tarball, not from a local archive — the two differ if
the tag moves:

```bash
curl -sL https://github.com/dhulabs/dhu-backup/archive/refs/tags/v0.3.0.tar.gz |
  shasum -a 256
```

Compare that hex string with the `sha256` line already in the formula; for a new tag, paste the new one over it.

## Updating for a new release

1. Tag and publish the release in `dhulabs/dhu-backup`.
2. Point `url` at the new tag and recompute `sha256` as above.
3. Re-read `caveats`: it names the install command, and a changed flag there is
   a changed instruction thousands of terminals will print.
4. `brew audit --strict --new dhu-backup` and `brew install --build-from-source`
   against the tap before pushing.

## Checking it locally

`ruby -c packaging/homebrew/dhu-backup.rb` parses the file without Homebrew.
`brew audit` and `brew style` need Homebrew and a tap that exists, so they are
run at publication time, not from this repository.
