#!/bin/sh
# Builds the Teleport VNet Android prototype: the Go library as an AAR, then the
# APKs. See README.md for prerequisites.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)

log() { printf 'build: %s\n' "$*"; }

: "${ANDROID_HOME:?set ANDROID_HOME to your Android SDK}"

if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    ANDROID_NDK_HOME=$(find "$ANDROID_HOME/ndk" -maxdepth 1 -mindepth 1 -type d | sort | tail -1)
    export ANDROID_NDK_HOME
fi
[ -n "$ANDROID_NDK_HOME" ] || { echo "build: no NDK found under $ANDROID_HOME/ndk" >&2; exit 1; }
log "using NDK $ANDROID_NDK_HOME"

# gomobile shells out to gobind, which has to be on PATH.
if ! command -v gobind >/dev/null 2>&1; then
    log "installing gobind"
    (cd "$repo" && go install golang.org/x/mobile/cmd/gobind)
    PATH="$(go env GOPATH)/bin:$PATH"
    export PATH
fi

log "building app/libs/vnet.aar"
mkdir -p "$here/app/libs"
# -ldflags="-s -w" is not optional: without it the Go shared library is over
# 130 MB per ABI, and Gradle cannot strip it because it is not a standard NDK
# build product.
(cd "$repo" && go tool gomobile bind \
    -target=android/arm64,android/amd64 \
    -androidapi 26 \
    -ldflags="-s -w" \
    -javapkg com.goteleport.vnet \
    -o "$here/app/libs/vnet.aar" \
    ./lib/mobile/vnet)

log "writing local.properties"
echo "sdk.dir=$ANDROID_HOME" > "$here/local.properties"

log "building APKs"
(cd "$here" && ${GRADLE:-gradle} :app:assembleDebug)

log "done:"
ls -lh "$here/app/build/outputs/apk/debug/"*.apk
