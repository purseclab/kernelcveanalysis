Normally, Chrome can be built from source using [these instructions](https://chromium.googlesource.com/chromium/src/+/main/docs/android_build_instructions.md). However, to build Chrome from source for older chrome versions, some updates need to be made. 

## Depot Tools
First, when installing depot_tools, make sure to checkout the most recent prior version to when the version of Chrome was released using the following command.
```bash
git checkout "$(git rev-list -n 1 --before="yyyy-mm-dd" origin/main)"
``` 

## Fetching
After fetching the code, checkout the correct version tag
```bash
git checkout {version}
```

## Altering the DEPS
Since a lot of files are no longer supported in Chrome, you may need to remove multiple dependencies from the DEPS file to build. For building Chrome 86.0.4240.30, I removed the following file(s)
  - tools_traffic_annotation_linux 

Removing render_test_goldens may not be necessary. There are also multiple other DEPS that are not found but can be built without, some of these files can be found in other databases, but are usually unecessary to building Chrome. 

For my patch look at [deps_changes.patch](deps_changes.patch).

It can be applied using
```bash
git am < deps_changes.patch
```

## Building
Build Chrome as normal. 