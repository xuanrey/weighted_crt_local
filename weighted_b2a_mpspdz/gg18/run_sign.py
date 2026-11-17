#!/usr/bin/env python3
"""Launch separate local GG18 processes after Section 5.2; read no private xi."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

# All elliptic-curve helpers below operate on PUBLIC verification data only.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3*x*x) * pow(2*y, -1, P) if a == b else
             (v-y) * pow(u-x, -1, P)) % P
    z = (slope*slope-x-u) % P
    return z, (slope*(x-z)-y) % P


def multiply(k, point):
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def main():
    if len(sys.argv) != 4:
        raise SystemExit('Usage: run_sign.py <gg18_party> <session_dir> <message>')
    executable, session, message = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(), sys.argv[3]
    if not executable.is_file():
        raise SystemExit('Build GG18 first: bash gg18/setup_gg18.sh')
    meta = json.loads((session / 'input/metrics.json').read_text())
    n = meta['mp_parties']
    digest = hashlib.sha256(message.encode('utf-8')).hexdigest()
    # Every attempt uses a fresh mailbox, so old messages cannot be replayed accidentally.
    mailbox = Path(tempfile.mkdtemp(prefix='gg18-mailbox.', dir=session))
    os.chmod(mailbox, 0o700)
    processes, captures = [], []
    started = time.perf_counter()
    try:
        for i in range(n):
            capture = tempfile.TemporaryFile(mode='w+', encoding='utf-8')
            captures.append(capture)
            processes.append(subprocess.Popen(
                [str(executable), str(session), str(i), str(n), digest, str(mailbox)],
                stdout=capture, stderr=subprocess.STDOUT))
        deadline = time.monotonic() + 1500
        while any(process.poll() is None for process in processes):
            if any(process.poll() not in (None, 0) for process in processes):
                raise RuntimeError('A GG18 participant failed')
            if time.monotonic() > deadline:
                raise RuntimeError('GG18 execution timed out')
            time.sleep(0.05)
        if any(process.returncode != 0 for process in processes):
            raise RuntimeError('A GG18 participant failed')
        elapsed = time.perf_counter() - started
        signatures = [json.loads((session / f'gg18/P{i}/signature.json').read_text())
                      for i in range(n)]
        signature = signatures[0]
        public_fields = ('digest_hex', 'r_hex', 's_hex', 'recovery_id',
                         'public_x_hex', 'public_y_hex', 'verified')
        if any(any(s[field] != signature[field] for field in public_fields) for s in signatures):
            raise RuntimeError('GG18 participants disagree on the signature or public key')
        public = (int(signature['public_x_hex'], 16), int(signature['public_y_hex'], 16))
        expected = None
        for i in range(n):
            lines = (mailbox / f'P{i}.public').read_text().splitlines()
            point = None if lines == ['infinity'] else (int(lines[0], 16), int(lines[1], 16))
            expected = add(expected, point)
        if expected != public:
            raise RuntimeError('Imported GG18 public key differs from sum(xi*G)')
        # This is a known demo input, not reconstructed from the exported xi.
        # It also checks that signing uses the original Section 5.1/5.2 secret.
        known_secret = sum(bit << k for k, bit in enumerate(meta['secret_coefficients'])) % Q
        if multiply(known_secret, G) != public:
            raise RuntimeError('GG18 public key differs from the known experiment input')
        r, s, z = int(signature['r_hex'], 16), int(signature['s_hex'], 16), int(digest, 16)
        if not 0 < r < Q or not 0 < s < Q:
            raise RuntimeError('ECDSA signature scalar out of range')
        w = pow(s, -1, Q)
        check = add(multiply(z*w % Q, G), multiply(r*w % Q, public))
        if check is None or check[0] % Q != r:
            raise RuntimeError('Independent public ECDSA verification failed')
        signature.update(message=message, parties=n, import_and_sign_wall_seconds=elapsed)
        result = session / 'gg18/signature.json'
        result.write_text(json.dumps(signature, indent=2) + '\n')
        print(f'GG18 import and signing {elapsed:.9f} s; signature verified')
        print(f'Public signature: {result}')
    except BaseException:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for i, capture in enumerate(captures):
            capture.seek(0)
            tail = ''.join(capture.readlines()[-15:])
            if tail:
                print(f'P{i}:\n{tail}', file=sys.stderr)
        raise
    finally:
        for capture in captures:
            capture.close()


if __name__ == '__main__':
    main()
