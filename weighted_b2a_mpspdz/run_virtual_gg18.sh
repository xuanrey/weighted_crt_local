#!/usr/bin/env bash
set -euo pipefail
umask 077

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
gg18="$here/gg18"
prefix=$(cd -- "$here/.." && pwd)/deps/install
jobs=${BUILD_JOBS:-2}
repeats=${REPEATS:-1}
message=${BENCH_MESSAGE:-Weighted GG18 benchmark}
[[ "$repeats" =~ ^[1-9][0-9]*$ && "$jobs" =~ ^[1-9][0-9]*$ ]] || {
    echo "REPEATS and BUILD_JOBS must be positive integers." >&2
    exit 1
}

# Label | physical weights | minimum signing weight | selected real IDs (1-based).
CASES=(
    'small|1,1,1|2|1,3'
    'weighted_9|1,4,5,2,3|9|2,3'
    'weighted_11|1,4,5,2,3|9|2,3,4'
)

if [[ ! -d "$prefix" ]]; then
    echo "Install the GG18 dependencies first: bash gg18/setup_gg18.sh" >&2
    exit 1
fi
export LD_LIBRARY_PATH="$prefix/lib:${LD_LIBRARY_PATH:-}"
cmake -S "$gg18" -B "$gg18/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$prefix"
cmake --build "$gg18/build" --target gg18_virtual_bench -j "$jobs"

mkdir -p "$here/runs"
output_dir=$(mktemp -d "$here/runs/virtual_gg18.XXXXXX")
results="$output_dir/results.csv"
printf '%s\n' 'case,trial,weights,threshold,selected_real_ids,real_parties,total_virtual_parties,real_signers,virtual_signers,initialization_seconds,signing_seconds' > "$results"
printf 'Results: %s\n' "$results"

for entry in "${CASES[@]}"; do
    IFS='|' read -r label weights threshold selected extra <<< "$entry"
    if [[ ! "$label" =~ ^[[:alnum:]_-]+$ || -z "$weights" || -z "$threshold" ||
          -z "$selected" || -n "$extra" ]]; then
        echo "Invalid case: $entry" >&2
        exit 1
    fi

    for ((trial = 1; trial <= repeats; ++trial)); do
        if ! output=$("$gg18/build/gg18_virtual_bench" "$weights" "$threshold" "$selected" "$message"); then
            printf '%s\n' "$output" >&2
            printf 'Failed case %s, trial %s. Completed trials: %s\n' "$label" "$trial" "$results" >&2
            exit 1
        fi
        initialization=$(awk -F= '$1 == "initialization_seconds" { print $2 }' <<< "$output")
        signing=$(awk -F= '$1 == "signing_seconds" { print $2 }' <<< "$output")
        real_parties=$(awk -F= '$1 == "real_parties" { print $2 }' <<< "$output")
        total_virtual_parties=$(awk -F= '$1 == "total_virtual_parties" { print $2 }' <<< "$output")
        real_signers=$(awk -F= '$1 == "real_signers" { print $2 }' <<< "$output")
        virtual_signers=$(awk -F= '$1 == "virtual_signers" { print $2 }' <<< "$output")
        if [[ ! "$initialization" =~ ^[0-9]+\.[0-9]+$ ||
              ! "$signing" =~ ^[0-9]+\.[0-9]+$ ||
              ! "$real_parties" =~ ^[1-9][0-9]*$ ||
              ! "$total_virtual_parties" =~ ^[1-9][0-9]*$ ||
              ! "$real_signers" =~ ^[1-9][0-9]*$ ||
              ! "$virtual_signers" =~ ^[1-9][0-9]*$ ]]; then
            printf 'Invalid benchmark output for %s, trial %s\n' "$label" "$trial" >&2
            exit 1
        fi
        printf '%s,%s,"%s",%s,"%s",%s,%s,%s,%s,%s,%s\n' \
            "$label" "$trial" "$weights" "$threshold" "$selected" \
            "$real_parties" "$total_virtual_parties" "$real_signers" "$virtual_signers" \
            "$initialization" "$signing" >> "$results"
        printf '%s trial %s (%s virtual signers)\n  Initialization: %s s\n  Signing:        %s s\n' \
            "$label" "$trial" "$virtual_signers" "$initialization" "$signing"
    done
done
