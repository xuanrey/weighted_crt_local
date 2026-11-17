#!/usr/bin/env bash
# Build one template specialization for the requested ORIGINAL user count.
# Usage: bash svole/setup_svole.sh [number_of_users]
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
root=$(cd -- "$here/../.." && pwd)
users=${1:-3}
[[ "$users" =~ ^[1-9][0-9]*$ ]] && (( users <= 39 )) || {
  echo "sVOLE supports 1 through 39 users in this local wrapper." >&2; exit 1;
}
source_dir="$root/deps/SIF-Implmentation"
revision=f9c969359c2445d77200ccea77de765c0a98943c
if [[ ! -d "$source_dir/.git" ]]; then
  mkdir -p "$root/deps"
  git clone https://github.com/ZheleiZhou/SIF-Implmentation.git "$source_dir"
fi
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || {
  echo "SIF checkout has local changes; preserve them before building." >&2; exit 1;
}
git -C "$source_dir" checkout --detach "$revision"
mkdir -p "$here/build"
python3 "$here/patch_sif.py" "$source_dir" "$here/build/overlay"
g++ -std=c++17 -O2 -march=native -Wno-deprecated-declarations -Wno-ignored-attributes \
  -DLOCALHOST -DTOTAL_PARTIES=$((users+1)) \
  -I"$here/build/overlay" -I"$source_dir" \
  -I"$source_dir/third_party/emp-tool" -I"$source_dir/third_party/emp-ot" \
  -I"$source_dir/third_party/emp-agmpc" \
  "$here/svole_party.cpp" "$source_dir/third_party/emp-tool/emp-tool/emp-tool.cpp" \
  -lssl -lcrypto -pthread -o "$here/build/svole-$users"
echo "sVOLE executable: $here/build/svole-$users"
