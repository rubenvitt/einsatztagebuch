#!/bin/sh
set -eu
cd "$(dirname "$0")"
output_dir=${1:-build}
mkdir -p "$output_dir"
module_dir=$(mktemp -d "${TMPDIR:-/tmp}/ea-native-macos-build.XXXXXXXX")
build_arch=$(uname -m)
trap 'rm -rf "$module_dir"' EXIT HUP INT TERM
xcrun swiftc -target "$build_arch-apple-macos13.0" -swift-version 6 -warnings-as-errors -O \
  -module-cache-path "$module_dir/modules" \
  Protocol.swift NativeAccount.swift Marker.swift Keychain.swift Provider.swift CodeIdentity.swift MonitorIPC.swift WatchSession.swift main.swift \
  -o "$output_dir/ea-native-operator"
xcrun swiftc -target "$build_arch-apple-macos13.0" -swift-version 6 -warnings-as-errors -O -lEndpointSecurity -D MONITOR_DAEMON \
  -module-cache-path "$module_dir/modules" Protocol.swift CodeIdentity.swift MonitorIPC.swift MonitorDaemon.swift main.swift \
  -o "$output_dir/ea-native-monitor"
