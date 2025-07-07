Normally, Chrome can be built from source using [these instructions](https://chromium.googlesource.com/chromium/src/+/main/docs/android_build_instructions.md). However, to build Chrome from source for older chrome versions, some updates need to be made. 

## Prerequisites
  - python-is-python3
  - ubuntu 20.04

## Fetching
After fetching the code, checkout the correct version tag
```bash
git checkout {version}
```

## Depot Tools
First, when installing depot_tools, make sure to checkout the most recent prior version to when the version of Chrome was released using the following command.
```bash
git checkout "$(git rev-list -n 1 --before="yyyy-mm-dd" origin/main)"
``` 
You want to change your checkout of Depot Tools after fetching the code. Older versions of depot tools fail to fetch from git because they are still using old origin/master naming convetions. This is likely very easy to patch but can be ignore by downgrading depot_tools only after fetching chrome source. 

## Altering the DEPS
Since a lot of files are no longer supported in Chrome, you may need to remove multiple dependencies from the DEPS file to build. For building Chrome 86.0.4240.30, I removed the following file(s)
  - tools_traffic_annotation_linux 

Removing render_test_goldens may not be necessary. There are also multiple other DEPS that are not found but can be built without, some of these files can be found in other databases, but are usually unecessary to building Chrome. 

For my patch look at [deps_changes.patch](deps_changes.patch).

It can be applied using
```bash
git apply deps_changes.patch
```

After applying the patch you can run `gclient sync --force` again. The current version of the patch keeps render test goldens, however, gclient will fail to fetch them. This can be removed from DEPS as they are not necessary to build anyway. 

## Building
Build Chrome as normal. 