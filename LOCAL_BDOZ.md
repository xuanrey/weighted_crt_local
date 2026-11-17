# Local BDOZ generation update

Based exclusively on the corrected upload `weighted_crt-main(1).zip`.

Chapter 5 and Chapter 6 retain their original MASCOT invocations. MASCOT still
produces random mask bits, correlated binary/arithmetic daBit shares, and
arithmetic MAC shares. The MPC sources no longer compute BDOZ DELTA/tag/key.
After all MPC parties succeed, `chapter5/local_bdoz.py` reads the exported bits
and generates their BDOZ authentication locally. It preserves arithmetic records
and publishes READY only after the local stage finishes. Existing C++ local
verification remains enabled and unchanged.

This is a TRUSTED local preprocessing simulation: the local process can read all
parties' binary shares and generates all BDOZ keys. It is not a secure distributed
replacement for MASCOT preprocessing without a trusted party. Keep all role files
private and use fresh material for each session.

VSS, Figure 10, GG18, CASES, DKG/signing orchestration and their timing formulas
are unchanged. Existing VSC offline time includes the local BDOZ stage. Raw MPC
Time10--13 exclude it; corresponding Python component fields add the local
compute time. Details are in preprocessing/TRUSTED_LOCAL_BDOZ.json. The original
DKG_total formula still excludes VSC offline; this update does not redefine it.

Run as before:

```bash
cd weighted_b2a_mpspdz
bash run_local.sh
```

The old chapter6/prep_estimate.py is unchanged, but its multiplication and time
estimate describes the OLD MPC-generated BDOZ path; do not use it to predict
this version. For n=4, d=1024, T=640, d0=256, explicit secret multiplications in
the revised preprocessing source are 2,560 rather than 2,755,072. Internal MPC
random-bit generation, checks and outputs still have costs; this is not a timing
prediction.

Validation:

```bash
python3 chapter6/test_local_bdoz.py
```

This executes both modified MPC sources in a cleartext test harness, attaches
local BDOZ, and runs the real C++ loader and Figure 8/9 conversion for three
parameter sets (six cases). It checks arithmetic material preservation, MACs,
conversion correctness, and tamper/reuse rejection. It is NOT a real MP-SPDZ
compiler/runtime test. The modified MASCOT program and full GG18 end-to-end
execution have not been tested in the editing environment.
