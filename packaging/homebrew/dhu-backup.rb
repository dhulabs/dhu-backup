# DHU Backup — Homebrew formula for the tap `dhulabs/homebrew-tap`.
#
# WHAT THIS DELIBERATELY DOES NOT DO: it does not install, register, start or
# touch the root daemon, and it never will. `brew install` runs as the user —
# the same principal a coding agent runs as — and the entire guarantee of this
# product is that the mirror is written by a SECOND principal that the user's
# own processes cannot stop, kill or write to. A formula that could set that up
# would be a path from an agent-writable package manager to root, which is the
# threat model inverted. Homebrew installs the FILES; a human types one sudo
# command afterwards, having read the script it runs.
#
# So `brew install dhu-backup` gets you the reader (`dhu-backup status`, `ls`,
# `log`, `cat`, `restore`, …) and the installer script on disk, and the caveats
# below tell you the one command that turns capture on.
class DhuBackup < Formula
  desc "Append-only mirror of the files a coding agent can delete, written by a root daemon"
  homepage "https://github.com/dhulabs/dhu-backup"
  url "https://github.com/dhulabs/dhu-backup/archive/refs/tags/v0.3.0.tar.gz"
  # The sha256 of the published v0.3.0 tarball, computed twice from
  #   curl -sL https://github.com/dhulabs/dhu-backup/archive/refs/tags/v0.3.0.tar.gz | shasum -a 256
  # on 2026-09-12 after the release was cut and again after the author-identity rewrite of the same day. A wrong checksum here fails the
  # install loudly; re-run that command against any new tag before bumping.
  sha256 "4f8f07b9f43f5ee28ba9f0966d3347bc0e8f1565b458c52b7ab335e2380f9a47"
  license "Apache-2.0"

  # No `depends_on "python"`. The daemon and the helpers run under the SYSTEM
  # interpreter with -E -s -S, by design: a root daemon executes only root-owned
  # bytes, and a Homebrew python lives in a directory the user's own account can
  # write. Adding it as a dependency would put the wrong interpreter first on
  # PATH for anyone reading these scripts.

  def install
    libexec.install Dir["*"]

    # A wrapper, NOT a symlink. `dhu-backup` puts its own directory on sys.path
    # to import `dhu_backup_core` and `dhu_backup_announce`, and it computes
    # that directory with `os.path.abspath(__file__)`, which does not resolve
    # symlinks — so a symlink in bin/ would make it search bin/ and fail to
    # import. The wrapper names the real path.
    (bin/"dhu-backup").write <<~SHELL
      #!/bin/bash
      exec /usr/bin/python3 -E -s -S "#{libexec}/src/dhu-backup.py" "$@"
    SHELL
  end

  def caveats
    <<~EOS
      This installed the READER only. Nothing is being captured yet, and
      `dhu-backup status` will say so (it exits 2 until a daemon is installed).

      Capture needs a root daemon, which is one deliberate sudo, by a human:

        sudo bash #{libexec}/src/install.sh --watch id=/abs/path

      Read that script before you run it. Running it with sudo is a one-time
      transfer of trust, there is no way around that for a root daemon, and it
      is kept short enough to read. It prints the owner, mode and sha256 of
      everything it installs, and asks you to type "yes" before it writes.

      See the whole plan first, unprivileged and changing nothing:

        bash #{libexec}/src/install.sh --dry-run --watch id=/abs/path

      There is no default watchlist on purpose: a default would name
      directories that do not exist on your machine, and the installer would
      report success over a store protecting nothing. Run it with no --watch
      and it refuses — and suggests candidates it found on this machine.
    EOS
  end

  test do
    # Against an install root that does not exist, so the answer is the same on
    # a machine that has the daemon and one that does not: no heartbeat, which
    # is exit code 2 ("could not determine"), not 1 ("not capturing").
    output = shell_output("#{bin}/dhu-backup --install-root #{testpath}/absent status", 2)
    assert_match "no-heartbeat", output
    assert_match "dhu-backup", shell_output("#{bin}/dhu-backup --help")
  end
end
