with import <nixpkgs> {}; let
  runtimeLibs = [ pkgconfig rustc cargo openssl gcc ];
  libPaths    = map (x: ":${x}/lib") runtimeLibs;
in rec {
  env = stdenv.mkDerivation {
    name            = "rust-dev";
    buildInputs     = [ stdenv ] ++ runtimeLibs;
    LD_LIBRARY_PATH = lib.foldl (x: y: x + y) "" libPaths;
    RUST_HOME       = rustc;
  };
}
