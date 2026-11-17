#!/usr/bin/env python3
"""Estimate preprocessing cost for one Chapter 6 parameter set.

Mirrors the formulas in chapter6/run_tests.py and the multiplication count
implied by chapter6/preprocess_ch6.mpc. Nothing is executed; this is pure
arithmetic so a configuration can be screened before spending real time.

Usage:
  prep_estimate.py T t min_bits weights_csv [selected_csv]

`selected_csv` defaults to all parties. IDs are zero-based and match CASES.

Calibration: the ms-per-multiplication figure is fitted from two measured
runs in this repository (4-party and 5-party, 256-bit field) and is accurate
to roughly +-10% in that regime. It is an estimate, not a measurement.
"""
import sys

FIELD_BITS = 128           # tag/key width
MULTS_PER_TAG_BIT = 2      # delta*b plus the product inside xor = a+b-2ab
# Fitted from runs/chapter6.umhD0b (N=4) and runs/chapter6.zFNrDM (N=5):
# ms per secret multiplication ~= K * (N-1)^2 for a 256-bit field.
K_MS = 0.113


def derive(T, t, minimum, weights, selected):
    n = len(weights)
    if not (0 < t < T):
        raise SystemExit(f'invalid T/t: need 0 < t < T, got t={t} T={T}')
    if max(weights) >= t:
        raise SystemExit(f'max(weight)={max(weights)} must be < t={t}')
    if sum(weights) < T + t:
        raise SystemExit(f'total weight {sum(weights)} < T+t={T + t}')
    if minimum < 256:
        raise SystemExit(f'min_bits={minimum} < 256, not valid for secp256k1')
    scale = max((10 + min(weights) - 1) // min(weights),
                (minimum + T - t - 1) // (T - t))
    d0 = scale * (T - t)
    deg = [weights[i] * scale for i in selected]
    h = (sum(weights[i] for i in selected) - T) * scale
    if h < 0:
        raise SystemExit('selected subset weight is below T')
    return scale, d0, deg, h, sum(weights[i] for i in selected)


def mults(N, total_deg, h, d0):
    """Secret multiplications per batch, from preprocess_ch6.mpc:18-26."""
    per_bit = (N - 1) * FIELD_BITS * MULTS_PER_TAG_BIT
    return {
        'R (input masks)': total_deg * per_bit,
        'Z (zero daBits)': N * h * per_bit,
        'B (b2a daBits)': N * d0 * per_bit,
    }


def main():
    if len(sys.argv) not in (5, 6):
        raise SystemExit(
            'usage: prep_estimate.py T t min_bits weights_csv [selected_csv]')
    T, t, minimum = map(int, sys.argv[1:4])
    weights = list(map(int, sys.argv[4].split(',')))
    n = len(weights)
    selected = (list(map(int, sys.argv[5].split(',')))
                if len(sys.argv) == 6 else list(range(n)))
    for i in selected:
        if i < 0 or i >= n:
            raise SystemExit(f'selected id {i} out of range for {n} parties')

    scale, d0, deg, h, wsel = derive(T, t, minimum, weights, selected)
    batches = mults(len(selected), sum(deg), h, d0)
    total = sum(batches.values())
    ms_per_mult = K_MS * (len(selected) - 1) ** 2
    seconds = total * ms_per_mult / 1000.0

    print(f'parties        : {len(selected)} of {n}  (selected {selected})')
    print(f'weights        : {[weights[i] for i in selected]}  total={wsel}')
    print(f'T / t          : {T} / {t}   (T+t={T + t}, T-t={T - t})')
    print(f'scale / d0     : {scale} / {d0}')
    print(f'degrees        : {deg}  sum={sum(deg)}')
    print(f'h (zero batch) : {h}')
    print()
    print(f'{"batch":<18}{"bits":>8}{"multiplications":>18}')
    bits = {'R (input masks)': sum(deg),
            'Z (zero daBits)': len(selected) * h,
            'B (b2a daBits)': len(selected) * d0}
    for name, value in batches.items():
        print(f'{name:<18}{bits[name]:>8}{value:>18,}')
    print(f'{"total":<18}{"":>8}{total:>18,}')
    print()
    print(f'ms per multiplication (est.) : {ms_per_mult:.2f}')
    print(f'estimated preprocessing time : {seconds:,.0f} s  '
          f'({seconds / 60:.1f} min, {seconds / 3600:.2f} h)')
    print('Estimate only: fitted from N=4/5, 256-bit runs in this repo.')


if __name__ == '__main__':
    main()
