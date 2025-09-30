{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.android-tools
    # pkgs.ruby
    pkgs.bundler
    pkgs.setools
  ];
  shellHook = ''
    bundle config set path ruby_gems
    bundle install
  '';
}

# Hack: inside nix shell, run `nix shell nixpkgs/24.05#rubyPackages.seccomp-tools`
# to get seccomp-tools, the default nixos seccomp-tools does not work
