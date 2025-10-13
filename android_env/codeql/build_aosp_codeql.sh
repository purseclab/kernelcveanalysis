#!/bin/bash

# use this as the codeql build command when creating a database
# example:
# codeql database create db.cql --language=java --command ./build_aosp_codeql.sh

CODEQL_DIST="/home/jack/codeql/codeql"
CODEQL_DB="/mnt/data/jroscoe/aosp/db.cql"

# set CODEQL_DIST and CODEQL_DB accordingly

ANDROID_ROOT="$(pwd)"
CODEQL_BINARY="$CODEQL_DIST/codeql"
ALT_JAVAC_PATH=$(mktemp -p /tmp codeql-javac.XXXXXXX)
chmod +x "$ALT_JAVAC_PATH"
cat > "$ALT_JAVAC_PATH" <<EOF
#!/bin/bash

# strip arguments with spaces
args=()
for i in "\$@"; do
  if [[ "\$i" =~ " " ]];
  then
    echo -n
  else
    args+=("\$i")
  fi
done
echo
export _JAVA_OPTIONS="-Xmx80000M"
"$CODEQL_BINARY" database trace-command \
  "$CODEQL_DB" \
  "$ANDROID_ROOT/prebuilts/jdk/jdk11/linux-x86/bin/javac" -- \
  "\${args[@]}"
EOF
source build/envsetup.sh 
export ALTERNATE_JAVAC="$ALT_JAVAC_PATH"
mm clean
# use x86_64 cause I wasn't sure if pizza would have arm compilers and such
lunch aosp_cf_x86_64_only_phone-userdebug
DISABLE_ARTIFACT_PATH_REQUIREMENTS=true m -j8 framework services # set number of threads in -j accordingly
