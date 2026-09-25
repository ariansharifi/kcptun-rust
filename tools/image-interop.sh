#!/usr/bin/env bash
# Docker-image-level interop: this image against the upstream Go image, in all four pairings,
# for both smux versions. Proves the "drop-in for the upstream image" claim of
# step 13.2 with real bytes through a real tunnel, rather than by
# inspecting the Dockerfile.
#
# The upstream image defaults to a DIFFERENT smux version than the kcptun this port targets
# (2023 builds default to -smuxver 1, the pinned 2026 reference to 2), so every pairing passes
# -smuxver explicitly. Two peers with mismatched smux versions do not interoperate in Go either;
# see the step 13.2 notes.
#
#   tools/image-interop.sh [rust-image] [go-image]
#
# Needs a working Docker daemon and network access to pull the Go image and two helpers.
set -uo pipefail

RS="${1:-kcptun-rust:smoke}"
GO="${2:-aguegu/kcptun:latest}"
NET=kcptun-interop-net
KEY='drop-in-test-key'
SIZE_MB=20
FAIL=0

cleanup() {
  docker rm -f ki-target ki-server ki-client >/dev/null 2>&1
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT INT TERM
cleanup

docker network create "$NET" >/dev/null || exit 1

# Target: an HTTP server holding a known random blob.
docker run -d --name ki-target --network "$NET" python:3-alpine sh -c "
  mkdir -p /srv && cd /srv &&
  dd if=/dev/urandom of=blob bs=1M count=$SIZE_MB status=none &&
  sha256sum blob > /srv/sum.txt &&
  exec python3 -m http.server 8080 --directory /srv" >/dev/null || exit 1

for i in $(seq 40); do
  EXPECT=$(docker exec ki-target cat /srv/sum.txt 2>/dev/null | awk '{print $1}')
  [ -n "${EXPECT:-}" ] && break
  sleep 1
done
[ -n "${EXPECT:-}" ] || { echo "target never became ready"; exit 1; }
echo "target ready, blob sha256 = ${EXPECT:0:16}…  (${SIZE_MB} MB)"
echo

run_pair() {
  local label="$1" simg="$2" cimg="$3"
  docker rm -f ki-server ki-client >/dev/null 2>&1

  docker run -d --name ki-server --network "$NET" "$simg" \
      /bin/server -t ki-target:8080 -l :29900 -key "$KEY" -mode fast3 -crypt aes -smuxver "$SMUXVER" >/dev/null
  docker run -d --name ki-client --network "$NET" "$cimg" \
      /bin/client -r ki-server:29900 -l :12948 -key "$KEY" -mode fast3 -crypt aes -smuxver "$SMUXVER" >/dev/null
  sleep 4

  local got
  got=$(docker run --rm --network "$NET" curlimages/curl:latest \
          -s --max-time 120 "http://ki-client:12948/blob" 2>/dev/null | sha256sum | awk '{print $1}')

  if [ "$got" = "$EXPECT" ]; then
    printf '  %-28s OK   (%s MB verified)\n' "$label" "$SIZE_MB"
  else
    printf '  %-28s FAIL got=%s\n' "$label" "${got:0:16}"
    echo "    --- server log ---"; docker logs ki-server 2>&1 | tail -5 | sed 's/^/    /'
    echo "    --- client log ---"; docker logs ki-client 2>&1 | tail -5 | sed 's/^/    /'
    FAIL=1
  fi
}

for SMUXVER in 1 2; do
  echo "image-level interop, -smuxver $SMUXVER (server image -> client image):"
  run_pair "rust server + rust client" "$RS" "$RS"
  run_pair "GO   server + rust client" "$GO" "$RS"
  run_pair "rust server + GO   client" "$RS" "$GO"
  run_pair "GO   server + GO   client" "$GO" "$GO"
  echo
done

echo
[ "$FAIL" -eq 0 ] && echo "ALL PAIRINGS PASSED" || echo "SOME PAIRINGS FAILED"
exit "$FAIL"
