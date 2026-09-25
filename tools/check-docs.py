#!/usr/bin/env python3
"""Generate and check the parts of the documentation that must not drift.

Usage:
    tools/check-docs.py                 # check everything, exit non-zero on a mismatch
    tools/check-docs.py --write         # regenerate the generated blocks in README.md
    tools/check-docs.py --print-flags   # print the flags table and exit
    tools/check-docs.py --bin-dir DIR   # where kcptun-client/kcptun-server live
                                        # (default: target/release)

Three things are checked:

  1. **The flags table in README.md is the real `-h` output.** It is parsed out of the two
     binaries rather than copied by hand, so a flag, a default or a description can never be
     documented as something the program does not print. Build first:
     `cargo build --release -p kcptun-client -p kcptun-server`.
  2. **The "Differences from Go" table in README.md lists every deviation.** `docs/DECISIONS.md`
     is the register of intentional behaviour deviations (V-xx); every id in it must appear in
     the README table and vice versa, so a new deviation cannot be added without telling users
     about it.
  3. **Relative links in the Markdown files resolve.** A link to a file that does not exist is an
     error.

Deliberately *not* checked: the wording of the README's difference summaries. They are written for
a reader who does not know the codebase, while DECISIONS.md is written for the porter; keeping the
ids in step is what matters mechanically.

Python 3.9+, standard library only (macOS ships 3.9; the repository's other helper scripts make
the same assumption).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
DECISIONS = ROOT / "docs" / "DECISIONS.md"

FLAGS_BEGIN = "<!-- BEGIN generated: flags (tools/check-docs.py) -->"
FLAGS_END = "<!-- END generated: flags -->"

# `   --localaddr value, -l value      local listen address (default: ":12948")`
OPTION_RE = re.compile(r"^ {3}(-\S.*?)(?: {2,}(.*))?$")
DEFAULT_RE = re.compile(r"\s*\(default: (.*)\)$")
ENVVAR_RE = re.compile(r"\s*\[\$([A-Z_]+)\]$")


class Option:
    """One `GLOBAL OPTIONS:` entry of a binary's `-h` output."""

    def __init__(self, names: str, description: str):
        self.names = names.strip()
        self.env = None
        self.default = None
        text = description.strip()
        m = ENVVAR_RE.search(text)
        if m:
            self.env = m.group(1)
            text = text[: m.start()]
        m = DEFAULT_RE.search(text)
        if m:
            self.default = m.group(1)
            text = text[: m.start()]
        self.description = text.strip()

    @property
    def key(self) -> str:
        """The primary flag name, e.g. `--localaddr` or `-c`."""
        return self.names.split(",")[0].split()[0]


def run_help(binary: Path) -> str:
    try:
        proc = subprocess.run(
            [str(binary), "-h"], capture_output=True, text=True, timeout=30, check=False
        )
    except FileNotFoundError:
        sys.exit(
            f"{binary} not found. Build it first:\n"
            f"  cargo build --release -p kcptun-client -p kcptun-server"
        )
    out = proc.stdout + proc.stderr
    if "GLOBAL OPTIONS:" not in out:
        sys.exit(f"{binary} -h printed no GLOBAL OPTIONS section:\n{out}")
    return out


def parse_options(help_text: str) -> "dict[str, Option]":
    options: dict[str, Option] = {}
    in_options = False
    for line in help_text.splitlines():
        if line.startswith("GLOBAL OPTIONS:"):
            in_options = True
            continue
        if not in_options:
            continue
        if line.strip() == "":
            continue
        m = OPTION_RE.match(line)
        if not m:
            continue
        opt = Option(m.group(1), m.group(2) or "")
        options[opt.key] = opt
    return options


def cell(value: "str | None") -> str:
    """A default value as a table cell. `None` means the flag takes no value."""
    if value is None:
        return "—"
    return f"`{value}`"


def flags_table(bin_dir: Path) -> str:
    client = parse_options(run_help(bin_dir / "kcptun-client"))
    server = parse_options(run_help(bin_dir / "kcptun-server"))

    # The client's order (its help is the longer one), with the server-only flags spliced in at
    # the first flag the two share — which puts `--listen`/`--target` next to the client's
    # `--localaddr`/`--remoteaddr` instead of stranding them at the end of the table.
    server_only = [k for k in server if k not in client]
    keys: list[str] = []
    for key in client:
        if key in server and server_only:
            keys += server_only
            server_only = []
        keys.append(key)
    keys += server_only

    lines = [
        "| Flag | Client default | Server default | Meaning |",
        "|---|---|---|---|",
    ]
    for key in keys:
        c = client.get(key)
        s = server.get(key)
        opt = c or s
        assert opt is not None
        names = f"`{opt.names}`"
        description = opt.description
        if opt.env:
            if not description.endswith((".", "!", "?")):
                description += "."
            description += f" Also read from `${opt.env}`."
        lines.append(
            f"| {names} | {cell(c.default) if c else 'n/a'} "
            f"| {cell(s.default) if s else 'n/a'} | {description} |"
        )
    return "\n".join(lines)


def replace_block(text: str, begin: str, end: str, body: str) -> str:
    start = text.index(begin) + len(begin)
    stop = text.index(end)
    return text[:start] + "\n" + body + "\n" + text[stop:]


def extract_block(text: str, begin: str, end: str, what: str) -> str:
    if begin not in text or end not in text:
        sys.exit(f"README.md has no {what} block ({begin} … {end})")
    start = text.index(begin) + len(begin)
    stop = text.index(end)
    return text[start:stop].strip("\n")


def decision_ids(text: str) -> "list[str]":
    return re.findall(r"^\| (V\d\d) \|", text, re.MULTILINE)


def check_differences(readme: str) -> "list[str]":
    problems = []
    declared = decision_ids(DECISIONS.read_text())
    if not declared:
        problems.append("docs/DECISIONS.md has no V-xx rows; the parser is wrong")
        return problems
    documented = set(re.findall(r"\*\*(V\d\d)\*\*", readme))
    missing = [v for v in declared if v not in documented]
    extra = sorted(documented - set(declared))
    if missing:
        problems.append(
            "README.md's differences table is missing "
            + ", ".join(missing)
            + " (every V-xx in docs/DECISIONS.md must be listed for users)"
        )
    if extra:
        problems.append(
            "README.md documents " + ", ".join(extra) + ", which docs/DECISIONS.md does not define"
        )
    return problems


LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def check_links() -> "list[str]":
    problems = []
    files = [README, ROOT / "CHANGELOG.md", *sorted((ROOT / "docs").rglob("*.md"))]
    for path in files:
        if not path.exists():
            problems.append(f"{path.relative_to(ROOT)} does not exist")
            continue
        for target in LINK_RE.findall(path.read_text()):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                problems.append(
                    f"{path.relative_to(ROOT)}: broken link to {target}"
                )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="rewrite the generated blocks")
    parser.add_argument("--print-flags", action="store_true", help="print the flags table")
    parser.add_argument(
        "--bin-dir",
        default=str(ROOT / "target" / "release"),
        help="directory holding kcptun-client and kcptun-server",
    )
    args = parser.parse_args()

    bin_dir = Path(args.bin_dir)

    if args.print_flags:
        print(flags_table(bin_dir))
        return 0

    readme = README.read_text()

    if args.write:
        updated = replace_block(readme, FLAGS_BEGIN, FLAGS_END, flags_table(bin_dir))
        if updated != readme:
            README.write_text(updated)
            print("README.md: flags table updated")
        else:
            print("README.md: flags table already up to date")
        readme = updated

    problems = []
    if extract_block(readme, FLAGS_BEGIN, FLAGS_END, "flags") != flags_table(bin_dir):
        problems.append(
            "README.md's flags table does not match the binaries' -h output; "
            "run tools/check-docs.py --write"
        )
    problems += check_differences(readme)
    problems += check_links()

    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    if problems:
        return 1
    print("docs OK: flags table, deviation list and links all check out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
