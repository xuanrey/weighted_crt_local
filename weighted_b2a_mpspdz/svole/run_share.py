#!/usr/bin/env python3
"""Generate real SIF authentication material, then run the local authenticated Share."""
import os
from pathlib import Path
import random
import socket
import subprocess
import sys
import tempfile
import time


def free_base_port(total):
    # The vendored NetIOMP uses base+2*(i*total+j), plus a second channel.
    for _ in range(100):
        base = random.randrange(15000, 40000)
        sockets = []
        try:
            for i in range(1, total+1):
                for j in range(i+1, total+1):
                    for extra in (0, 1):
                        sock = socket.socket()
                        sockets.append(sock)
                        sock.bind(('127.0.0.1', base+2*(i*total+j)+extra))
            return base
        except OSError:
            pass
        finally:
            for sock in sockets:
                sock.close()
    raise RuntimeError('Cannot find free local sVOLE ports')


def main():
    if len(sys.argv) != 9:
        raise SystemExit('Usage: run_share.py cpp input_dir T t min_bits weights_csv ids_csv secret_csv')
    cpp, directory, *parameters = sys.argv[1:]
    directory = Path(directory).resolve()
    command = [str(Path(cpp).resolve()), str(directory), *parameters]
    subprocess.run(command + ['prepare'], check=True)
    # Each dealer has fresh authentication/session material but identical public moduli.
    shared = os.environ.get('CH6_SHARED_PARAMETERS')
    if shared:
        own = (directory/'parameters.txt').read_text().splitlines()
        common = Path(shared).read_text().splitlines()
        if own[0].split()[1:] != common[0].split()[1:]:
            raise RuntimeError('Shared DKG parameters mismatch')
        (directory/'parameters.txt').write_text(own[0]+'\n'+'\n'.join(common[1:])+'\n')
    n, T, sid = (directory / 'auth_dimensions.txt').read_text().split()
    n, T = int(n), int(T)
    if n > 39:
        raise SystemExit('This local SIF wrapper supports at most 39 users plus one dealer')
    here = Path(__file__).resolve().parent
    binary = here / f'build/svole-{n}'
    sources = [here / name for name in ('svole_party.cpp', 'patch_sif.py', 'setup_svole.sh')]
    if not binary.exists() or any(p.stat().st_mtime > binary.stat().st_mtime for p in sources):
        with tempfile.TemporaryFile(mode='w+') as capture:
            result = subprocess.run(['bash', str(here/'setup_svole.sh'), str(n)],
                                    stdout=capture, stderr=subprocess.STDOUT)
            if result.returncode:
                capture.seek(0)
                print(''.join(capture.readlines()[-40:]), file=sys.stderr)
                raise SystemExit(result.returncode)
    auth_directory = directory / 'auth'
    auth_directory.mkdir(mode=0o700)
    port = free_base_port(n+1)
    processes, captures = [], []
    started = time.perf_counter()
    try:
        for role in range(1, n+2):
            capture = tempfile.TemporaryFile(mode='w+')
            captures.append(capture)
            processes.append(subprocess.Popen(
                [str(binary), str(role), str(port), str(T), sid, str(auth_directory)],
                stdout=capture, stderr=subprocess.STDOUT))
        deadline = time.monotonic()+1200
        while any(p.poll() is None for p in processes):
            if any(p.poll() not in (None, 0) for p in processes):
                raise RuntimeError('A real sVOLE participant failed')
            if time.monotonic() > deadline:
                raise RuntimeError('sVOLE preprocessing timed out')
            time.sleep(0.02)
        if any(p.returncode for p in processes):
            raise RuntimeError('A real sVOLE participant failed')
        # Diagnostic only: preprocessing is excluded from the Share benchmark.
        (directory/'auth_preprocessing_seconds.txt').write_text(str(time.perf_counter()-started)+'\n')
    except BaseException:
        for p in processes:
            if p.poll() is None:
                p.terminate()
        for p in processes:
            try:
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        for role, capture in enumerate(captures, 1):
            capture.seek(0)
            tail = ''.join(capture.readlines()[-20:])
            if tail:
                print(f'sVOLE role {role}:\n{tail}', file=sys.stderr)
        raise
    finally:
        for capture in captures:
            capture.close()
    subprocess.run(command + ['share'], check=True)


if __name__ == '__main__':
    os.umask(0o077)
    main()
