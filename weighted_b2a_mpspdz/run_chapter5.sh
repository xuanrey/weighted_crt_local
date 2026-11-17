#!/usr/bin/env bash
set -euo pipefail
umask 077
bundle_dir=$(cd -- "$(dirname -- "$0")" && pwd)
# Edit this path to your existing MP-SPDZ installation.
# MP_SPDZ_DIR="${CH5_MP_SPDZ_DIR:-$HOME/MP-SPDZ}"
MP_SPDZ_DIR=${MP_SPDZ_DIR:-"$bundle_dir/../MP-SPDZ-master"}
# 'authenticated' preserves the original real sVOLE Chapter 4 input route.
# 'fixture' tests Chapter 5 with honestly generated CRT inputs, without claiming VSS.
INPUT_MODE="${CH5_INPUT_MODE:-authenticated}"
# Small prime for functional experiments. For secp256k1 ECDSA use the order below,
# and set min_bits >=256 in EVERY CASES row (paper's d0 >= ceil(log2 q)).
Q=2305843009213693951
# Q=115792089237316195423570985008687907852837564279074904382605163141518161494337
# name|T|t|min_bits|weights_csv|selected_ids_csv|secret_bits_csv
# Zero-based IDs. A row is rejected when T <= selected weight < T+t.
# Only successful rows print timings; rejected or failed rows print the reason.
CASES=(
  "case_01|8|3|256|1,6,9,12,17|0,1,2,3|1,0,1,1"
  # "case_02|3|1|61|2,2,1|0,2|1,0,1,1"
  # "case_03|3|1|61|2,3,1|0,1|1,1,0,1"
)
[[ $# == 0 ]] || { echo 'Edit CASES in run_local.sh; no CLI arguments.' >&2; exit 1; }
[[ "$INPUT_MODE" == authenticated || "$INPUT_MODE" == fixture ]] || exit 1
[[ -x "$MP_SPDZ_DIR/mascot-party.x" && -f "$MP_SPDZ_DIR/compile.py" ]] || {
  echo 'Set MP_SPDZ_DIR and build mascot-party.x first.' >&2; exit 1;
}
mkdir -p "$bundle_dir/runs"
batch=$(mktemp -d "$bundle_dir/runs/chapter5.XXXXXX")
g++ -std=c++17 -O2 -Wall -Wextra "$bundle_dir/main.cpp" -lcrypto -lgmpxx -lgmp -o "$batch/weighted_crt"
for line in "${CASES[@]}"; do
  IFS='|' read -r name T t min_bits weights ids secret extra <<< "$line"
  [[ -n "$secret" && -z "${extra:-}" && "$name" =~ ^case_[0-9]+$ ]] || {
    echo "Malformed CASES row (expected 7 fields, name case_<n>): $line" >&2; exit 1;
  }
  echo "Experiment: $name"
  python3 "$bundle_dir/chapter5/run_case.py" "$batch/weighted_crt" "$MP_SPDZ_DIR" "$batch" \
    "$name" "$T" "$t" "$min_bits" "$weights" "$ids" "$secret" "$Q" "$INPUT_MODE"
done
echo "Results: $batch/results.csv"
