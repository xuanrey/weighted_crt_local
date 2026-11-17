#!/usr/bin/env bash
set -euo pipefail
umask 077
bundle_dir=$(cd -- "$(dirname -- "$0")" && pwd)
MP_SPDZ_DIR=${MP_SPDZ_DIR:-"$bundle_dir/../MP-SPDZ-master"}
DEPS_PREFIX=${DEPS_PREFIX:-"$bundle_dir/../deps/install"}
export LD_LIBRARY_PATH="$DEPS_PREFIX/lib:$MP_SPDZ_DIR:${LD_LIBRARY_PATH:-}"
# One DKG per row. Semicolon-separated signing sets reuse that DKG.
# name|T|t|min_bits|weights_csv|sign_sets
# Scaled gap >=256. Includes two authorized sets, a repeat, and a rejected set.
CASES=(
  'case_01|512|256|256|179,191,197,201|0,1,2'
  'case_02|768|512|256|307,313,329,331|0,1,2'
  # 'case_03|896|640|256|367,379,389,401|0,1,2;0,1'
  # 'case_04|1280|1024|256|551,569,583,601|0,1,2;2,3'
)
[[ $# == 0 ]] || { echo 'Edit CASES; no command-line arguments.' >&2; exit 1; }
[[ -x "$MP_SPDZ_DIR/mascot-party.x" ]] || { echo 'Set MP_SPDZ_DIR.' >&2; exit 1; }
mkdir -p "$bundle_dir/build" "$bundle_dir/runs"
g++ -std=c++17 -O2 "$bundle_dir/main.cpp" -lcrypto -lgmpxx -lgmp -o "$bundle_dir/build/weighted_crt"
g++ -std=c++17 -O2 -I"$DEPS_PREFIX/include" "$bundle_dir/chapter6/main.cpp" \
  -L"$DEPS_PREFIX/lib" -Wl,-rpath,"$DEPS_PREFIX/lib" \
  -lMultiPartySig -lSafeheronCryptoSuites -lprotobuf -lcrypto -lgmpxx -lgmp -pthread \
  -o "$bundle_dir/build/chapter6"
batch=$(mktemp -d "$bundle_dir/runs/chapter6.XXXXXX")
for row in "${CASES[@]}"; do
  IFS='|' read -r name T t min_bits weights sets extra <<< "$row"
  [[ "$name" =~ ^case_[0-9]+$ && -n "$sets" && -z "${extra:-}" ]] || exit 1
  python3 "$bundle_dir/chapter6/run_tests.py" "$bundle_dir/build/weighted_crt" \
    "$bundle_dir/build/chapter6" "$MP_SPDZ_DIR" "$batch/$name" \
    "$T" "$t" "$min_bits" "$weights" "$sets"
done
