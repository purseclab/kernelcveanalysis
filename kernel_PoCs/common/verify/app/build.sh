#!/usr/bin/env bash
# Rebuild the tiny debuggable helper APK used by --from-app.
# Requires ANDROID_SDK_ROOT (or ANDROID_HOME), javac, keytool, zip, and SDK
# build-tools. The checked-in APK is built with build-tools 35.0.0 and API 33.
set -euo pipefail

app_dir=$(cd -- "$(dirname -- "$0")" && pwd)
verify_dir=$(cd -- "$app_dir/.." && pwd)
sdk=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}
if [[ -z $sdk ]]; then
    echo "set ANDROID_SDK_ROOT or ANDROID_HOME" >&2
    exit 1
fi
build_tools=${BUILD_TOOLS:-$sdk/build-tools/35.0.0}
android_jar=${ANDROID_JAR:-$sdk/platforms/android-33/android.jar}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

mkdir -p "$out/classes" "$out/dex"
mapfile -t java_sources < <(find "$app_dir/src" -name '*.java' -print)
javac -source 8 -target 8 -classpath "$android_jar" -d "$out/classes" \
    "${java_sources[@]}"
mapfile -t class_files < <(find "$out/classes" -name '*.class' -print)
"$build_tools/d8" --lib "$android_jar" --output "$out/dex" "${class_files[@]}"
"$build_tools/aapt2" link -o "$out/base.apk" \
    --manifest "$app_dir/AndroidManifest.xml" -I "$android_jar"
(cd "$out/dex" && zip -q "$out/base.apk" classes.dex)
"$build_tools/zipalign" -f 4 "$out/base.apk" "$out/aligned.apk"
if [[ ! -f $out/debug.keystore ]]; then
    keytool -genkeypair -keystore "$out/debug.keystore" \
        -storepass android -keypass android -alias androiddebugkey \
        -keyalg RSA -keysize 2048 -validity 10000 \
        -dname 'CN=Android Debug,O=Android,C=US' >/dev/null 2>&1
fi
mkdir -p "$verify_dir/src/verify_kernel_poc/assets"
"$build_tools/apksigner" sign \
    --ks "$out/debug.keystore" --ks-pass pass:android --key-pass pass:android \
    --ks-key-alias androiddebugkey --v4-signing-enabled false \
    --out "$verify_dir/src/verify_kernel_poc/assets/kpoc-verify.apk" \
    "$out/aligned.apk"
echo "wrote $verify_dir/src/verify_kernel_poc/assets/kpoc-verify.apk"
