#!/bin/sh
# Own disposable resources only; does not inspect/stop existing services.
set -eu
ea_source=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
ea_token=$(date +%s)-$$
ea_image=ea-native-linux-test:$ea_token
ea_container=ea-native-linux-test-$ea_token
cleanup() {
    docker rm -f "$ea_container" >/dev/null 2>&1 || true
    docker image rm "$ea_image" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
docker build --label ea.native-test="$ea_token" -t "$ea_image" "$ea_source"
docker run --name "$ea_container" --label ea.native-test="$ea_token" \
    --mount "type=bind,source=$ea_source,target=/source,readonly" \
    -e EA_DISPOSABLE_TEST=1 "$ea_image"
