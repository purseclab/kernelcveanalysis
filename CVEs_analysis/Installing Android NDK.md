The easiest way is to install the android sdk manager CLI tool by following these directions: https://developer.android.com/tools/sdkmanager

Then use sdkmanager to install NDK
List packages:
```sh
./bin/sdkmanager --list
```

Install packages:
```sh
./bin/sdkmanager --install "ndk;25.2.9519653"
```