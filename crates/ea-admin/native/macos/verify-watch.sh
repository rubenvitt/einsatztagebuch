#!/bin/sh
set -eu
cd "$(dirname "$0")"
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/ea-native-watch-test.XXXXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
xcrun swiftc -swift-version 6 -warnings-as-errors -module-cache-path "$build_dir/modules" -lEndpointSecurity -D WATCH_STATE_TEST \
  Protocol.swift NativeAccount.swift Marker.swift Keychain.swift Provider.swift CodeIdentity.swift MonitorIPC.swift WatchSession.swift MonitorDaemon.swift WatchTests.swift main.swift \
  -o "$build_dir/watch-state-tests"
"$build_dir/watch-state-tests"
xcrun swiftc -swift-version 6 -warnings-as-errors -module-cache-path "$build_dir/modules" -D WATCH_TEST \
  Protocol.swift NativeAccount.swift Marker.swift Keychain.swift Provider.swift CodeIdentity.swift MonitorIPC.swift WatchSession.swift WatchTests.swift main.swift \
  -o "$build_dir/watch-fixture"
python3 watch_protocol_tests.py "$build_dir/watch-fixture"
sh build.sh "$build_dir/production"
python3 protocol_tests.py "$build_dir/production/ea-native-operator"
PYTHONDONTWRITEBYTECODE=1 python3 release_tests.py
