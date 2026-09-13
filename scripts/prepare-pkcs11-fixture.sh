#!/usr/bin/env bash
# Explicit isolated Stage-5 test fixture. No system install or production key.
set -euo pipefail
task_root="$(cd "$(dirname "$0")/.." && pwd)"
fixture_root="$task_root/.superpowers/pkcs11-fixture-v1"
mkdir -p "$fixture_root"
if [[ ! -d "$fixture_root/source" ]]; then
  curl --fail --silent --show-error --location \
    https://codeload.github.com/softhsm/SoftHSMv2/tar.gz/refs/tags/2.7.0 \
    --output "$fixture_root/softhsm-2.7.0.tar.gz"
  python3 - "$fixture_root" <<'PY'
import hashlib, pathlib, sys, tarfile
root = pathlib.Path(sys.argv[1])
archive = root / 'softhsm-2.7.0.tar.gz'
assert hashlib.sha256(archive.read_bytes()).hexdigest() == 'be14a5820ec457eac5154462ffae51ba5d8a643f6760514d4b4b83a77be91573'
with tarfile.open(archive) as tar:
    # Also supports the system Python on macOS. The pinned archive contains
    # only regular files/directories; reject link and traversal members.
    for item in tar.getmembers():
        assert item.isfile() or item.isdir()
        (root / item.name).resolve().relative_to(root.resolve())
    tar.extractall(root)
(root / 'SoftHSMv2-2.7.0').rename(root / 'source')
PY
fi
cmake_options=(-DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DENABLE_EDDSA=ON -DENABLE_ECC=ON)
if [[ "$(uname -s)" == Darwin && -d /opt/homebrew/opt/openssl@3 ]]; then
  cmake_options+=(-DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3)
fi
cmake -S "$fixture_root/source" -B "$fixture_root/build" "${cmake_options[@]}"
cmake --build "$fixture_root/build" --parallel 4
module="$fixture_root/build/src/lib/libsofthsm2.so"
if [[ "$(uname -s)" == Darwin ]]; then module="$fixture_root/build/src/lib/libsofthsm2.dylib"; fi
test -f "$module"
umask 077
mkdir -p "$fixture_root/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' "$fixture_root/tokens" > "$fixture_root/softhsm2.conf"
export SOFTHSM2_CONF="$fixture_root/softhsm2.conf"
export EA_TEST_PKCS11_MODULE="$module"
if [[ ! -f "$fixture_root/initialized" ]]; then
  "$fixture_root/build/src/bin/util/softhsm2-util" --module "$module" --init-token --free \
    --label drk250-fixture --so-pin 12345678 --pin 12345678
  touch "$fixture_root/initialized"
fi
printf 'export SOFTHSM2_CONF=%q\nexport EA_TEST_PKCS11_MODULE=%q\nexport EA_TEST_PKCS11_TOKEN=drk250-fixture\n' "$SOFTHSM2_CONF" "$module" > "$fixture_root/env.sh"
cd "$task_root"
cargo run --locked -p ea-recovery --features pkcs11-fixture --example pkcs11_fixture
printf 'Fixture ready; source .superpowers/pkcs11-fixture-v1/env.sh before the explicit provider and CLI gates.\n'
