#!/usr/bin/env bash
# Check the GitHub Actions workflows in .github/workflows against the repository they describe.
#
# Usage: tools/check-workflows.sh
#
# These workflows cannot be run anywhere yet (the repository has no remote), so nothing else
# notices when they drift away from the tree. This script checks the invariants that matter and
# that a YAML linter cannot know about:
#
#   1. every cargo-fuzz target declared in crates/*/fuzz/Cargo.toml is fuzzed by fuzz.yml, and
#      fuzz.yml names no target that does not exist;
#   2. release.yml is triggered by workflow_dispatch and nothing else (no tag push, no schedule),
#      and its publishing job is still behind the RELEASE_PUBLISH_ENABLED kill switch;
#   3. ci.yml runs the three gate commands of docs/porting-guide.md §10, verbatim, and release.yml
#      asks tools/release.sh only for target groups that script still defines;
#   4. every workflow declares read-only default permissions;
#   5. `actionlint` passes, if it is installed (https://github.com/rhysd/actionlint). It lints the
#      `run:` scripts with shellcheck as well, when that is on PATH too.
#
# Works with macOS's bash 3.2 (no mapfile, no associative arrays).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WF="$ROOT/.github/workflows"

fail=0
err() {
  printf 'check-workflows: %s\n' "$1" >&2
  fail=1
}
log() { printf '==> %s\n' "$*"; }

for f in ci.yml interop.yml fuzz.yml release.yml; do
  [[ -f "$WF/$f" ]] || err "missing workflow: .github/workflows/$f"
done
[[ $fail -eq 0 ]] || exit 1

# ---------------------------------------------------------------------------------------------
# 1. The fuzz matrix covers exactly the cargo-fuzz targets that exist.
# ---------------------------------------------------------------------------------------------
log "fuzz.yml covers every cargo-fuzz target"

# `[[bin]] name = "..."` in each fuzz crate's manifest is the target name cargo-fuzz uses.
declared="$(grep -h '^name = ' "$ROOT"/crates/*/fuzz/Cargo.toml |
  sed 's/^name = "\(.*\)"$/\1/' |
  grep -v -- '-fuzz$' | sort -u)"
# `target: <name>` in the fuzz.yml matrix entries.
listed="$(grep -E '^[[:space:]]+target: ' "$WF/fuzz.yml" | sed 's/^[[:space:]]*target: //' | sort -u)"

for t in $declared; do
  case " $(echo "$listed" | tr '\n' ' ') " in
    *" $t "*) ;;
    *) err "fuzz target '$t' exists but fuzz.yml does not run it" ;;
  esac
done
for t in $listed; do
  case " $(echo "$declared" | tr '\n' ' ') " in
    *" $t "*) ;;
    *) err "fuzz.yml runs '$t', which no crates/*/fuzz/Cargo.toml declares" ;;
  esac
done

# Each target must be given its committed seed corpus, which is what a cold cache starts from.
for t in $declared; do
  found=0
  for d in "$ROOT"/crates/*/fuzz/seeds/"$t"; do
    [[ -d "$d" ]] && found=1
  done
  [[ $found -eq 1 ]] || err "fuzz target '$t' has no committed seed corpus (crates/*/fuzz/seeds/$t)"
done

# ---------------------------------------------------------------------------------------------
# 2. release.yml cannot fire by accident and cannot publish by accident.
# ---------------------------------------------------------------------------------------------
log "release.yml is manual-only and still gated"

# The trigger block is everything from `on:` to the first following top-level key.
triggers="$(awk '/^on:/{i=1;next} /^[a-z]/{i=0} i' "$WF/release.yml" | grep -E '^  [a-z_]+:' | sed 's/[: ]//g' | sort -u)"
if [[ "$triggers" != "workflow_dispatch" ]]; then
  err "release.yml must be triggered by workflow_dispatch only, found: $(echo "$triggers" | tr '\n' ' ')"
fi
if grep -qE '^[[:space:]]*tags(-ignore)?:' "$WF/release.yml"; then
  err "release.yml has a tag filter: a pushed tag must never be able to publish a release"
fi
if ! grep -qF "vars.RELEASE_PUBLISH_ENABLED == 'true'" "$WF/release.yml"; then
  err "release.yml has lost the RELEASE_PUBLISH_ENABLED kill switch on the publish job's 'if:'"
fi
if ! grep -qF 'RELEASE_PUBLISH_ENABLED is not' "$WF/release.yml"; then
  err "release.yml has lost the RELEASE_PUBLISH_ENABLED check in the guard job"
fi

# Only the publish job of release.yml may ask for write access.
for f in ci.yml interop.yml fuzz.yml; do
  if grep -q 'contents: write' "$WF/$f"; then
    err "$f requests write permissions; CI must be read-only"
  fi
done

# ---------------------------------------------------------------------------------------------
# 3. ci.yml runs the gate of docs/porting-guide.md §10, verbatim.
# ---------------------------------------------------------------------------------------------
log "ci.yml runs the gate commands verbatim"

# Match only against what ci.yml actually *runs*, not against the whole file: the header of ci.yml
# quotes all three gate commands in a comment, so a search over the file would pass even if every
# `run:` step were deleted. This extracts the body of every `run:` directive, both the one-line
# form (`- run: cargo ...`) and the block form (`run: |` followed by an indented script).
ci_runs="$(awk '
  # `run: |` or `run: >` - a block scalar; its body is everything indented past the directive.
  /^[[:space:]]*(- )?run:[[:space:]]*[|>]/ { inblock = 1; indent = match($0, /[^ ]/); next }
  # `run: <command>` on one line.
  /^[[:space:]]*(- )?run:[[:space:]]*[^|>[:space:]]/ {
    sub(/^[[:space:]]*(- )?run:[[:space:]]*/, ""); print; next
  }
  inblock {
    if ($0 ~ /^[[:space:]]*$/) { next }          # blank lines do not end a block scalar
    if (match($0, /[^ ]/) <= indent) { inblock = 0; next }
    print
  }
' "$WF/ci.yml")"

while IFS= read -r cmd; do
  printf '%s\n' "$ci_runs" | grep -qF -- "$cmd" ||
    err "ci.yml does not run the gate command: $cmd"
done <<'EOF'
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
EOF

# ---------------------------------------------------------------------------------------------
# 3b. release.yml asks tools/release.sh for target groups that still exist.
# ---------------------------------------------------------------------------------------------
log "release.yml's target groups exist in tools/release.sh"

if [[ ! -x "$ROOT/tools/release.sh" ]]; then
  err "tools/release.sh is missing or not executable; release.yml runs it"
else
  groups="$("$ROOT/tools/release.sh" --list-groups)"
  # Only what release.yml *runs*, so the prose in its header cannot satisfy this check.
  while IFS= read -r line; do
    args="${line#*tools/release.sh }"
    for w in $args; do
      case "$w" in
        -*) continue ;;      # an option
        *[\$]*) continue ;; # the version argument, or any other shell expansion
      esac
      printf '%s\n' "$groups" | grep -qx -- "$w" ||
        err "release.yml asks tools/release.sh for '$w', which is neither a group nor an option"
    done
  done < <(grep -E '^[[:space:]]*(- )?run:[[:space:]]*tools/release\.sh ' "$WF/release.yml")
fi

# ---------------------------------------------------------------------------------------------
# 4. Read-only default permissions everywhere.
# ---------------------------------------------------------------------------------------------
log "every workflow defaults to read-only permissions"
for f in ci.yml interop.yml fuzz.yml release.yml; do
  awk '/^permissions:/{i=1;next} /^[a-z]/{i=0} i' "$WF/$f" | grep -q 'contents: read' ||
    err "$f has no top-level 'permissions: contents: read'"
done

# ---------------------------------------------------------------------------------------------
# 5. actionlint, when available.
# ---------------------------------------------------------------------------------------------
if command -v actionlint >/dev/null 2>&1; then
  log "actionlint $(actionlint -version | head -1)"
  actionlint "$WF"/*.yml || fail=1
else
  log "actionlint not installed - skipping (see https://github.com/rhysd/actionlint)"
fi

if [[ $fail -ne 0 ]]; then
  echo "check-workflows: FAILED" >&2
  exit 1
fi
log "workflows OK"
