{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.jdk17
    # pkgs.androidenv.androidPkgs.androidsdk
    # pkgs.androidenv.androidPkgs.platform-tools
    # pkgs.androidenv.androidPkgs.tools
    # pkgs.android-sdk-platform-tools
    # pkgs.android-sdk-cmdline-tools-latest
  ];

  # ANDROID_HOME = "${pkgs.androidsdk}/libexec/android-sdk";
  # ANDROID_SDK_ROOT = "${pkgs.androidsdk}/libexec/android-sdk";
}
