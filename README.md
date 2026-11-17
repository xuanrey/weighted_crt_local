# Weighted Threshold ECDSA (PolyCRT)

Research prototype for a weighted threshold ECDSA scheme built on Polynomial-CRT
secret sharing. Chapter 4 provides weighted verifiable sharing; Chapters 5 and 6
convert the accepted shares into additive and Shamir form (Figures 7-9), run a
distributed key generation (Figure 10), and sign with GG18.

Only the online phases are simulated locally inside a single process. All
preprocessing material is produced by MP-SPDZ's MASCOT and consumed from disk,
so every offline number in `results.csv` is measured rather than modelled.

## Requirements

| Component | Note |
|---|---|
| MP-SPDZ | checkout with `mascot-party.x` and `compile.py` built |
| C++ | C++17 compiler (`g++ -std=c++17`) |
| OpenSSL | `libssl-dev` |
| GMP | `libgmp-dev`, `libgmpxx` |
| Python | 3.8+, standard library only |
| GG18 dependencies | Safeheron and Protobuf, installed by `gg18/setup_gg18.sh` |
| CMake, make, pkg-config, git | needed once to build the GG18 dependencies |

Run everything on Linux, or on Ubuntu under WSL.

## 1. Configure MP-SPDZ

Place the checkout at `MP-SPDZ-master/`, next to `weighted_b2a_mpspdz/`, and
build MASCOT:

```bash
cd MP-SPDZ-master
make -j2 mascot-party.x
test -x mascot-party.x && test -f compile.py
cd ..
```

To use a checkout stored elsewhere, export its path before running:

```bash
export MP_SPDZ_DIR="$HOME/MP-SPDZ"
```

## 2. Configure the GG18 dependencies

```bash
cd weighted_b2a_mpspdz
bash gg18/setup_gg18.sh
```

This builds the pinned Safeheron and Protobuf sources into `deps/install/`.
Set `DEPS_PREFIX` if they live somewhere else; the same variable is honoured by
`run_local.sh` and `run_virtual_gg18.sh`.

## 3. Configure the experiment

Edit the `CASES` array in `weighted_b2a_mpspdz/run_local.sh`. One row performs
exactly one DKG and then every listed signing session against that same key:

```
name|T|t|min_bits|weights_csv|sign_sets
case_01|5|3|256|2,2,2,2|0,1,2;1,2,3
```

- `name` must match `case_[0-9]+`
- party IDs are zero-based and correspond to positions in `weights_csv`
- `;` separates signing sessions, which share the DKG but consume fresh preprocessing
- a session is reported as `rejected` when its weight is below `T` or it lists fewer than two parties

Start-up rejects configurations that violate any of:

```
0 < t < T              max(weight) < t
sum(weight) >= T+t     min_bits >= 256
```

Derived quantities, for reference:

```
scale      = max(ceil(10/min_weight), ceil(min_bits/(T-t)))
d0         = scale * (T-t)
degrees[i] = scale * weights[i]
h          = (sum(weight) - T) * scale
```

## 4. Run

```bash
cd weighted_b2a_mpspdz
bash run_local.sh
```

The script builds both binaries, runs one authenticated VSS per party, prepares
VSC material with MASCOT for every session, then executes the DKG and the GG18
signing rounds. The first run also compiles the sVOLE helper for the current
party count, which takes a few minutes; later runs reuse it.

## Outputs

Each batch creates `weighted_b2a_mpspdz/runs/chapter6.XXXXXX/`:

```
case_01/
  results.csv          timings, one row per stage
  dealer-<j>/          accepted CRT share and secret for each VSS dealer
  dkg/                 Figure 10 material, preprocessing, context.json, logs
  sign_<NN>/           one directory per signing session
  public_key.txt       the DKG public key
  vss_seconds.txt      sum of all dealers' Share timers
  vss_wall_seconds.txt measured wall clock of the VSS phase
```

`results.csv` columns:

```
stage,name,VSS,VSC_offline,VSC_online,Figure10_extra,DKG_total,
GG18_aux_offline,sign_total,status
```

`DKG_total = VSS + VSC_online + Figure10_extra`. VSS is the sum of the per-dealer
Share timers, a serial cost model; `vss_wall_seconds.txt` holds the measured
elapsed time when dealers run concurrently. `VSC_offline` covers MASCOT
preprocessing plus the Figure 8/9 setup and is *not* part of `DKG_total`.
`GG18_aux_offline` is the one-time Paillier and range-proof material, shared by
every signing session.

## Other entry points

| Command | Purpose |
|---|---|
| `bash run_virtual_gg18.sh` | GG18 virtualisation baseline over virtual parties, timings only |

## Known limitations

- The online phases of Chapters 5 and 6 run in one process with a trusted
  simulator; only preprocessing is real multi-party computation.
- Rebasing the signing-session preprocessing onto the DKG verification key is a
  simulator operation, not a cross-key protocol.
- The GG18 auxiliary material comes from an unmodified key generation over
  physical parties; its unrelated ECDSA shares are discarded and replaced.
- `GG18` sources keep their own licences, see `gg18/THIRD_PARTY_NOTICES.md`.
