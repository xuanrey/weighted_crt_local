#!/usr/bin/env python3
"""MASCOT arithmetic + trusted local BDOZ + local Figure 8/9 simulation."""
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import random
import re
import shutil
import socket
import subprocess
import sys
import time
from local_bdoz import attach_local_bdoz

TIME_FIELDS = (
    'preprocessing_key_setup', 'preprocessing_input_masks',
    'preprocessing_zero_dabits', 'preprocessing_b2a_dabits',
    'preprocessing_wall',
    'figure8_setup', 'figure8_test_convert', 'figure8_test_reconstruction',
    'figure9_setup', 'figure9_test_convert', 'figure9_test_reconstruction',
    'offline', 'convention_online',
)


def run_preprocessing(mp, session, context, source=None):
    n = len(context['degrees'])
    source = Path(source) if source else Path(__file__).with_name('preprocess_ch5.mpc')
    digest = hashlib.sha256(source.read_bytes()).hexdigest()[:12]
    # Compiler name includes source and field so cached schedules cannot cross contexts.
    name = 'ch5prep_' + digest + '_' + hashlib.sha256(context['q'].encode()).hexdigest()[:8]
    shutil.copyfile(source, mp/'Programs/Source'/f'{name}.mpc')
    args = [','.join(map(str, context['degrees'])), str(context['h']), str(context['d0'])]
    program = '-'.join([name, *args])
    if not (mp/'Programs/Schedules'/f'{program}.sch').exists():
        with (session/'compile.log').open('w') as log:
            result = subprocess.run([sys.executable, './compile.py', '-P', context['q'], name, *args],
                                    cwd=mp, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError('MPC compilation failed: ' + str(session/'compile.log'))
    for _ in range(100):
        port = random.randrange(15000, 45000)
        sockets = []
        try:
            for j in range(n+1):
                s = socket.socket()
                sockets.append(s)
                s.bind(('127.0.0.1', port+j))
            break
        except OSError:
            continue
        finally:
            for s in sockets:
                s.close()
    else:
        raise RuntimeError('No free local port range')
    pre = session/'preprocessing'
    pre.mkdir(mode=0o700)
    env = dict(os.environ)
    env['LD_LIBRARY_PATH'] = str(mp)+':'+env.get('LD_LIBRARY_PATH','')
    processes, logs = [], []
    start = time.perf_counter()
    try:
        for i in range(n):
            log = (session/f'mpc-P{i}.log').open('w')
            logs.append(log)
            processes.append(subprocess.Popen([
                str(mp/'mascot-party.x'), str(i), program, '-N', str(n),
                '-pn', str(port), '-h', 'localhost', '-OF', str(pre/'private'),
                '--batch-size', '1000'], cwd=mp, env=env, stdout=log, stderr=subprocess.STDOUT))
        deadline = time.monotonic()+3600
        while any(p.poll() is None for p in processes):
            if any(p.poll() not in (None,0) for p in processes):
                raise RuntimeError('MASCOT party failed; inspect mpc-P*.log')
            if time.monotonic() > deadline:
                raise RuntimeError('MASCOT preprocessing timed out')
            time.sleep(.05)
        if any(p.returncode for p in processes):
            raise RuntimeError('MASCOT failed')
    finally:
        for p in processes:
            if p.poll() is None:
                p.terminate()
        for p in processes:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        for log in logs:
            log.close()
    wall = time.perf_counter()-start
    times = {k: [] for k in (10,11,12,13)}
    for i in range(n):
        log = (session/f'mpc-P{i}.log').read_text()
        for k in times:
            found = re.findall(r'^Time#?'+str(k)+r'\s*=\s*([\d.eE+-]+)\s*seconds',log,re.M)
            if len(found)!=1 or not math.isfinite(float(found[0])) or float(found[0])<0:
                raise RuntimeError(f'Missing/invalid timer {k}, party {i}')
            times[k].append(float(found[0]))
        private = pre/f'private-P{i}-0'
        if not private.is_file():
            raise RuntimeError(f'Missing private output for P{i}')
        lines = private.read_text().splitlines()
        # Discard only runtime banner lines. Every record must have an integer value.
        records = [line for line in lines if re.fullmatch(r'[A-Z0-9_]+=-?\d+', line)]
        if not records:
            raise RuntimeError('Empty preprocessing output')
        (pre/f'role-{i}.txt').write_text('\n'.join(records)+'\n')
        private.unlink()
    local_start = time.perf_counter()
    local_times = attach_local_bdoz(pre, context)
    wall += time.perf_counter()-local_start
    (pre/'TRUSTED_LOCAL_BDOZ.json').write_text(json.dumps({
        'mode': 'trusted_local_bdoz_with_mascot_arithmetic',
        'local_bdoz_seconds': local_times,
        'trust': 'Local generator reads all binary shares; not distributed malicious-secure preprocessing.'
    }, indent=2))
    # No output file is accepted before MPC and local BDOZ generation finish.
    (pre/'READY').write_text(context['sid']+' '+context['q']+'\n')
    return {'preprocessing_wall':wall,
            'preprocessing_key_setup':max(times[10]) + local_times["key_setup"],
            'preprocessing_input_masks':max(times[11]) + local_times["input_masks"],
            'preprocessing_zero_dabits':max(times[12]) + local_times["zero_dabits"],
            'preprocessing_b2a_dabits':max(times[13]) + local_times["b2a_dabits"]}


def run_step(args, label):
    """Run one stage; on failure keep only the tail of its output as the reason."""
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        tail = [line for line in (result.stdout + result.stderr).strip().splitlines() if line]
        detail = ' | '.join(tail[-3:]) if tail else 'no output'
        raise RuntimeError(f'{label} exited {result.returncode}: {detail}')
    return result


def collect(batch):
    results = [json.loads(f.read_text()) for f in sorted(batch.glob('*/result.json'))]
    fields = list(dict.fromkeys(k for r in results for k in r))
    with (batch/'results.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)


def run_case(cpp, mp, batch, name, T, t, minimum, weights, ids, secret, q, mode):
    session = batch/name
    session.mkdir(mode=0o700)
    # Weight preflight avoids spending Chapter 4/MPC preprocessing on rejected rows.
    ws = list(map(int, weights.split(',')))
    selected = list(map(int, ids.split(',')))
    if len(set(selected)) != len(selected) or any(i < 0 or i >= len(ws) for i in selected):
        raise RuntimeError(f'invalid selected IDs: {ids}')
    weight = sum(ws[i] for i in selected)
    cmd = [str(cpp), 'prepare', str(session), T, t, minimum, weights, ids, secret, q, mode]
    rejected = int(T) <= weight < int(T) + int(t)
    if rejected:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 42:
            detail = (result.stdout + result.stderr).strip() or 'no output'
            raise RuntimeError(
                f'weight {weight} lies in [T, T+t) but prepare exited {result.returncode}: {detail}')
        print(f'{name}: rejected, T <= selected weight {weight} < T+t; no timings')
        return {'case': name, 'status': 'expected_weight_rejection', 'selected_weight': weight,
                'T': int(T), 't': int(t), 'input_mode': mode}
    if mode == 'authenticated':
        root = Path(__file__).resolve().parent.parent
        run_step([sys.executable, str(root/'svole/run_share.py'), str(cpp), str(session/'ch4'),
                  T, t, minimum, weights, ids, secret], 'Chapter 4 sVOLE')
    run_step(cmd, 'prepare')
    context = json.loads((session/'context.json').read_text())
    offline = run_preprocessing(mp, session, context)
    run_step([str(cpp), 'execute', str(session)], 'execute')
    online = json.loads((session/'online_metrics.json').read_text())
    row = {'case': name, 'status': 'passed', 'selected_weight': weight, 'T': int(T),
           't': int(t), 'input_mode': mode, **offline, **online}
    # Actual preprocessing wall time includes runtime preparation, checks and private
    # exports. Compiler time and Chapter 4 are excluded. VM sub-timers are diagnostics.
    row['offline'] = offline['preprocessing_wall'] + online['figure8_setup'] + online['figure9_setup']
    row['timing_scope'] = 'local_online_simulation_trusted_BDOZ_MASCOT_arithmetic'
    print(f'{name}:')
    for key in TIME_FIELDS:
        print(f'  {key}: {row[key]:.9f} s')
    return row


def main():
    if len(sys.argv) != 13:
        raise SystemExit('usage: run_case.py cpp mp batch name T t min_bits weights ids '
                         'secret q mode')
    cpp, mp, batch, name, T, t, minimum, weights, ids, secret, q, mode = sys.argv[1:]
    cpp, mp, batch = map(lambda x: Path(x).resolve(), (cpp, mp, batch))
    try:
        row = run_case(cpp, mp, batch, name, T, t, minimum, weights, ids, secret, q, mode)
    except Exception as error:
        print(f'{name}: FAILED: {error}', file=sys.stderr)
        try:
            (batch/name).mkdir(parents=True, exist_ok=True)
            (batch/name/'result.json').write_text(json.dumps(
                {'case': name, 'status': 'failed', 'T': int(T), 't': int(t),
                 'input_mode': mode, 'reason': str(error)}, indent=2)+'\n')
            collect(batch)
        except Exception as record_error:
            print(f'{name}: could not record the failure: {record_error}', file=sys.stderr)
        raise SystemExit(1)
    (batch/name/'result.json').write_text(json.dumps(row, indent=2)+'\n')
    collect(batch)


if __name__ == '__main__':
    os.umask(0o077)
    main()
