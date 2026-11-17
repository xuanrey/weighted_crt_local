"""Trusted local BDOZ generation over MPC-exported bits. Not a distributed protocol.

Never publish READY here: the caller does so only after all stages succeed.
Arithmetic values/MAC shares are preserved byte-for-byte.
"""
import secrets
import time
from pathlib import Path


def attach_local_bdoz(directory, context):
    directory = Path(directory)
    if (directory / 'READY').exists():
        raise ValueError('Refusing to reauthenticate published material')
    degrees = context['degrees']
    n = len(degrees)
    h, d0 = context['h'], context['d0']
    if n < 2 or h < 0 or d0 <= 0 or any(d <= 0 for d in degrees):
        raise ValueError('Invalid dimensions')
    paths = [directory / f'role-{i}.txt' for i in range(n)]
    original = [p.read_text() for p in paths]
    records = []
    for text in original:
        record = {}
        for line in text.splitlines():
            key, value = line.split('=', 1)
            if key in record or key.startswith('DELTA_') or '_M_' in key or '_K_' in key:
                raise ValueError('Duplicate or existing BDOZ material')
            record[key] = int(value)
        records.append(record)
    # Validate all expected bits before producing any new files.
    for i in range(n):
        for kind, length in [('R', degrees[i]), ('Z', h), ('B', d0)]:
            for k in range(length):
                if records[i].get(f'{kind}_B_{k}') not in (0, 1):
                    raise ValueError('Missing or non-binary MPC output')
    chunk = min(32, int(context['q']).bit_length() - 1)
    added = [[] for _ in range(n)]

    def emit128(owner, label, value):
        for off in range(0, 128, chunk):
            added[owner].append(f'{label}_{off}={(value >> off) & ((1 << min(chunk, 128-off))-1)}\n')

    timings = {}
    start = time.perf_counter()
    delta = [secrets.randbits(128) for _ in range(n)]
    for i in range(n):
        emit128(i, 'DELTA', delta[i])
    timings['key_setup'] = time.perf_counter() - start
    for kind, field in [('R', 'input_masks'), ('Z', 'zero_dabits'), ('B', 'b2a_dabits')]:
        start = time.perf_counter()
        for i in range(n):
            length = degrees[i] if kind == 'R' else h if kind == 'Z' else d0
            for k in range(length):
                bit = records[i][f'{kind}_B_{k}']
                for j in range(n):
                    if i == j:
                        continue
                    tag = secrets.randbits(128)
                    key = tag ^ (delta[j] if bit else 0)
                    emit128(i, f'{kind}_M_{j}_{k}', tag)
                    emit128(j, f'{kind}_K_{i}_{k}', key)
        timings[field] = time.perf_counter() - start
    for p, text, extra in zip(paths, original, added):
        temporary = p.with_suffix('.local-bdoz.tmp')
        with temporary.open('x') as f:
            temporary.chmod(0o600)
            f.write(text + ('' if text.endswith('\n') else '\n') + ''.join(extra))
        temporary.replace(p)
    return timings
