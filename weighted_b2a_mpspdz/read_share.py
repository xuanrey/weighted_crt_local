#!/usr/bin/env python3
"""Read one owner's MP-SPDZ output as a canonical decimal secp256k1 scalar.
Usage: python3 read_share.py /path/to/output-P0-0
The full private key is never reconstructed here.
"""
import re
import sys
from pathlib import Path

Q = 115792089237316195423570985008687907852837564279074904382605163141518161494337
if len(sys.argv) != 2:
    raise SystemExit('Usage: python3 read_share.py <own-output-Pi-0>')
text = Path(sys.argv[1]).read_text()
values = re.findall(r'^X_SHARE_DECIMAL=(-?\d+)\s*$', text, flags=re.MULTILINE)
if len(values) != 1:
    raise SystemExit('Expected exactly one X_SHARE_DECIMAL output')
# Python integers have arbitrary precision; modulo also normalizes negative output.
print(int(values[0]) % Q)
