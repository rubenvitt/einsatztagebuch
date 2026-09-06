#!/bin/sh
set -eu
cd "$(dirname "$0")"
# Default suite is deterministic: SELF_TEST injects synthetic account and
# backup-policy values. Live OS probes are in verify-host-read-only.sh only.
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/ea-native-macos-test.XXXXXXXX")
trap 'rm -rf "$build_dir"' EXIT HUP INT TERM
xcrun swiftc -swift-version 6 -warnings-as-errors -module-cache-path "$build_dir/modules" \
  -typecheck Protocol.swift NativeAccount.swift Marker.swift Keychain.swift Provider.swift CodeIdentity.swift MonitorIPC.swift WatchSession.swift main.swift
xcrun swiftc -swift-version 6 -warnings-as-errors -module-cache-path "$build_dir/modules" \
  -lEndpointSecurity -D SELF_TEST Protocol.swift NativeAccount.swift Marker.swift Keychain.swift Provider.swift CodeIdentity.swift MonitorIPC.swift WatchSession.swift MonitorDaemon.swift WatchTests.swift SelfTests.swift main.swift \
  -o "$build_dir/self-tests"
"$build_dir/self-tests"
xcrun swiftc -swift-version 6 -O -module-cache-path "$build_dir/modules" \
  Protocol.swift NativeAccount.swift Marker.swift Keychain.swift Provider.swift CodeIdentity.swift MonitorIPC.swift WatchSession.swift main.swift \
  -o "$build_dir/ea-native-operator"
python3 protocol_tests.py "$build_dir/ea-native-operator"
xcrun swiftc -swift-version 6 -warnings-as-errors -module-cache-path "$build_dir/modules" -D WATCH_TEST \
  Protocol.swift NativeAccount.swift Marker.swift Keychain.swift Provider.swift CodeIdentity.swift MonitorIPC.swift WatchSession.swift WatchTests.swift main.swift \
  -o "$build_dir/watch-fixture"
python3 watch_protocol_tests.py "$build_dir/watch-fixture"
xcrun swiftc -swift-version 6 -warnings-as-errors -O -lEndpointSecurity -D MONITOR_DAEMON -module-cache-path "$build_dir/modules" \
  Protocol.swift CodeIdentity.swift MonitorIPC.swift MonitorDaemon.swift main.swift -o "$build_dir/ea-native-monitor"
PYTHONDONTWRITEBYTECODE=1 python3 release_tests.py
# Keep the manual probe compile-checked without running live directory APIs.
xcrun swiftc -swift-version 6 -warnings-as-errors -module-cache-path "$build_dir/modules" -D NATIVE_READ_ONLY_TEST \
  -typecheck Protocol.swift NativeAccount.swift Marker.swift Keychain.swift NativeReadOnlyTests.swift main.swift
