#!/usr/bin/env bash
# Build pinned GG18 dependencies locally; no upstream source patch is required.
# Prerequisites: g++, make, cmake, git, pkg-config, and OpenSSL development files.
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../.." && pwd)
deps="$root/deps"
prefix="$deps/install"
jobs="${BUILD_JOBS:-2}"
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo "BUILD_JOBS must be positive" >&2; exit 1; }
mkdir -p "$deps"

# Safeheron's generated sources support Protobuf 3.14/3.20, not arbitrary versions.
# Use a private 3.20.3 installation instead of replacing the system Protobuf.
if [[ ! -d "$deps/protobuf/.git" ]]; then
  git clone --depth 1 --branch v3.20.3 https://github.com/protocolbuffers/protobuf.git "$deps/protobuf"
fi
[[ "$(git -C "$deps/protobuf" describe --tags --exact-match)" == "v3.20.3" ]] || {
  echo "Expected Protobuf v3.20.3 in $deps/protobuf" >&2; exit 1;
}
cmake -S "$deps/protobuf/cmake" -B "$deps/protobuf/build" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
  -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_SHARED_LIBS=ON
cmake --build "$deps/protobuf/build" -j "$jobs"
cmake --install "$deps/protobuf/build"

export PATH="$prefix/bin:$PATH"
export LD_LIBRARY_PATH="$prefix/lib:${LD_LIBRARY_PATH:-}"
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
# Full commit IDs make the adapter's upstream assumptions reproducible.
crypto_ref=c05c0907ac6875ce4e1f5bbb4fcababcca5c71cf
sig_ref=e848e9353a6b59277e77f4b3060cb5ca608c7e00
for item in "safeheron-crypto-suites-cpp:$crypto_ref" "multi-party-sig-cpp:$sig_ref"; do
  repository=${item%%:*}
  revision=${item#*:}
  if [[ ! -d "$deps/$repository/.git" ]]; then
    git clone "https://github.com/Safeheron/$repository.git" "$deps/$repository"
  fi
  # Refuse to overwrite local edits in a dependency checkout.
  [[ -z "$(git -C "$deps/$repository" status --porcelain)" ]] || {
    echo "Dependency checkout has local changes: $repository" >&2; exit 1;
  }
  git -C "$deps/$repository" checkout --detach "$revision"
  # Explicit cstdint inclusion also supports newer GCC versions.
  cmake -S "$deps/$repository" -B "$deps/$repository/build" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DCMAKE_PREFIX_PATH="$prefix" -DENABLE_TESTS=OFF \
    "-DCMAKE_CXX_FLAGS=-include cstdint"
  cmake --build "$deps/$repository/build" -j "$jobs"
  cmake --install "$deps/$repository/build"
done
cmake -S "$here" -B "$here/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$prefix"
cmake --build "$here/build" -j "$jobs"
echo "GG18 executable: $here/build/gg18_party"
