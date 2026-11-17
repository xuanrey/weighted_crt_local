#!/usr/bin/env bash
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
prefix=${DEPS_PREFIX:-"$here/../../deps/install"}
export LD_LIBRARY_PATH="$prefix/lib:${LD_LIBRARY_PATH:-}"
mkdir -p "$here/../build"
g++ -std=c++17 -O2 -I"$prefix/include" "$here/test_protocol.cpp" -L"$prefix/lib" \
  -lMultiPartySig -lSafeheronCryptoSuites -lprotobuf -lcrypto -lgmpxx -lgmp -pthread \
  -o "$here/../build/test_chapter6"
"$here/../build/test_chapter6"
