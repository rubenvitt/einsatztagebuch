#!/bin/sh
set -eu
cd "$(dirname "$0")"
# Manual host probe: reads actual OpenDirectory and checks Foundation backup
# policy on disposable /private/tmp files. Never invokes Keychain/LA/ES APIs.
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/ea-native-host-test.XXXXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
xcrun swiftc -swift-version 6 -warnings-as-errors -module-cache-path "$build_dir/modules" -D NATIVE_READ_ONLY_TEST \
  Protocol.swift NativeAccount.swift Marker.swift Keychain.swift NativeReadOnlyTests.swift main.swift \
  -o "$build_dir/native-read-only-tests"
"$build_dir/native-read-only-tests"
