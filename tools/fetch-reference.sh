#!/usr/bin/env bash
# Fetch the pinned Go reference implementation of kcptun, vendor its exact dependencies,
# clone the latest upstream libraries (for reading post-pin fixes), build reference
# binaries and record a `go test` baseline. Everything goes to ./reference (gitignored).
#
# The GitHub repository xtaci/kcptun no longer exists; the last full-code version is
# only available from the Go module proxy, which is why we download the module zip.
#
# Usage: tools/fetch-reference.sh [--skip-latest] [--skip-tests] [--force]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REF="$ROOT/reference"

KCPTUN_MOD="github.com/xtaci/kcptun"
KCPTUN_VER="v0.0.0-20260208051026-39935d5307f0"            # commit 39935d5307f003e3a157ba1d684c2d4658b827b2
KCPTUN_ZIP_SHA256="c6340091d4b3fc93b414b4189f24157be064ff7cacb1a15b84e44162f1c10aef"
KCPTUN_H1="h1:fUzKdn1akLOYWtx6yuO4TqCy4T2R2/jDjdkYjXhXLlg="    # sum.golang.org
LATEST_REPOS=(kcp-go smux qpp tcpraw)
TARGETS=(darwin/arm64 linux/arm64 linux/amd64)

SKIP_LATEST=0 SKIP_TESTS=0 FORCE=0
for arg in "$@"; do
  case "$arg" in
    --skip-latest) SKIP_LATEST=1 ;;
    --skip-tests) SKIP_TESTS=1 ;;
    --force) FORCE=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# Keep the user's global module cache untouched.
export GOFLAGS=-modcacherw GOTOOLCHAIN=local GOMODCACHE="$REF/gomod"
export GOPROXY="${GOPROXY:-https://proxy.golang.org,direct}"

log() { printf '==> %s\n' "$*"; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

mkdir -p "$REF/bin" "$REF/latest"

# 1. kcptun module zip from the Go module proxy (verified by SHA-256).
if [[ $FORCE -eq 1 || ! -f "$REF/kcptun/go.mod" ]]; then
  log "downloading $KCPTUN_MOD@$KCPTUN_VER"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL -o "$tmp/kcptun.zip" "https://proxy.golang.org/$KCPTUN_MOD/@v/$KCPTUN_VER.zip"
  got="$(sha256 "$tmp/kcptun.zip")"
  if [[ "$got" != "$KCPTUN_ZIP_SHA256" ]]; then
    echo "SHA-256 mismatch for kcptun module zip: got $got, want $KCPTUN_ZIP_SHA256" >&2
    exit 1
  fi
  (cd "$tmp" && unzip -q kcptun.zip)
  rm -rf "$REF/kcptun"
  mv "$tmp/$KCPTUN_MOD@$KCPTUN_VER" "$REF/kcptun"
  chmod -R u+w "$REF/kcptun"
else
  log "kcptun source already present (use --force to re-download)"
fi

# 2. Vendor the exact dependency versions from go.mod / go.sum.
log "vendoring dependencies"
(cd "$REF/kcptun" && go mod vendor)

# 3. Latest upstream libraries, for reading fixes made after the pinned versions.
if [[ $SKIP_LATEST -eq 0 ]]; then
  for r in "${LATEST_REPOS[@]}"; do
    if [[ -d "$REF/latest/$r/.git" ]]; then
      log "updating latest/$r"
      git -C "$REF/latest/$r" pull -q --ff-only
    else
      log "cloning latest/$r"
      git clone -q "https://github.com/xtaci/$r.git" "$REF/latest/$r"
    fi
  done
fi

# 4. Reference binaries.
cd "$REF/kcptun"
for t in "${TARGETS[@]}"; do
  os="${t%/*}" arch="${t#*/}"
  for b in client server; do
    log "building ${b}_${os}_${arch}"
    GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -mod=vendor -trimpath -o "$REF/bin/${b}_${os}_${arch}" "./$b"
  done
done

# 5. Go interop peers and vector generator, once they exist (Step 01).
if [[ -d "$ROOT/tools/gointerop" && -f "$ROOT/tools/gointerop/go.mod" ]]; then
  for t in "${TARGETS[@]}"; do
    os="${t%/*}" arch="${t#*/}"
    for d in "$ROOT"/tools/gointerop/cmd/*/; do
      [[ -d "$d" ]] || continue
      name="$(basename "$d")"
      log "building gointerop ${name}_${os}_${arch}"
      (cd "$ROOT/tools/gointerop" && GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -o "$REF/bin/${name}_${os}_${arch}" "./cmd/$name")
    done
  done
fi

# 6. Record exact versions.
{
  echo "kcptun $KCPTUN_VER"
  echo "  module zip sha256 $KCPTUN_ZIP_SHA256"
  echo "  sum.golang.org   $KCPTUN_H1"
  echo "vendored modules (reference/kcptun/vendor/modules.txt):"
  grep '^# ' "$REF/kcptun/vendor/modules.txt" | sed 's/^# /  /'
  if [[ $SKIP_LATEST -eq 0 ]]; then
    echo "latest upstream clones:"
    for r in "${LATEST_REPOS[@]}"; do
      echo "  $r $(git -C "$REF/latest/$r" describe --tags --always) $(git -C "$REF/latest/$r" rev-parse HEAD)"
    done
  fi
  echo "built with $(go version)"
} > "$REF/VERSIONS.txt"
log "wrote reference/VERSIONS.txt"

# 7. Baseline: the reference's own tests.
if [[ $SKIP_TESTS -eq 0 ]]; then
  log "running go test ./... (baseline, output in reference/go-test.txt)"
  if go test -mod=vendor -count=1 ./... > "$REF/go-test.txt" 2>&1; then
    log "go test: PASS"
  else
    log "go test: FAIL (see reference/go-test.txt)"
  fi
fi

"$REF/bin/client_$(go env GOHOSTOS)_$(go env GOHOSTARCH)" -v
