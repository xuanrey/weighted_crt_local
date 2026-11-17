#!/usr/bin/env python3
"""One DKG, multiple signer sets; real sVOLE/MASCOT, local online simulation."""
import hashlib, json, os, re, secrets, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'chapter5'))
from run_case import run_preprocessing
Q='115792089237316195423570985008687907852837564279074904382605163141518161494337'
def run(args,log,env=None):
    with log.open('w') as f:
        p=subprocess.run(list(map(str,args)),stdout=f,stderr=subprocess.STDOUT,env=env)
    if p.returncode: raise RuntimeError(f'{log}: '+ '\n'.join(log.read_text().splitlines()[-12:]))
def main():
    if len(sys.argv)!=10:
        raise SystemExit('Usage: run_tests.py cpp ch6 mp out T t min_bits weights_csv sign_sets')
    cpp,ch6,mp,out,T,t,minimum,weights,sets=sys.argv[1:]
    out=Path(out).resolve();out.mkdir(parents=True,mode=0o700)
    mp=Path(mp).resolve();ws=list(map(int,weights.split(',')));n=len(ws)
    T,t,minimum=map(int,(T,t,minimum))
    if not (0<t<T and max(ws)<t and sum(ws)>=T+t and minimum>=256):
        raise ValueError('Require max(weight)<t, total>=T+t, min_bits>=256')
    scale=max((10+min(ws)-1)//min(ws),(minimum+T-t-1)//(T-t))
    d0=scale*(T-t);ids=','.join(map(str,range(n)))
    concurrency=int(os.environ.get('CH6_VSS_WORKERS',2))

    def run_dealer(j):
        print(f'Dealer {j+1}/{n}: VSS',flush=True)
        env=dict(os.environ)
        # Never inherit a shared-parameter pointer from a previous dealer.
        env.pop('CH6_SHARED_PARAMETERS',None)
        if j:env['CH6_SHARED_PARAMETERS']=str(out/'dealer-0/parameters.txt')
        secret=','.join(str(secrets.randbits(1)) for _ in range(d0))
        dealer_dir=out/f'dealer-{j}';dealer_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
        (dealer_dir/'secret.txt').write_text(secret+'\n')
        log=out/f'dealer-{j}.log'
        run([sys.executable,ROOT/'svole/run_share.py',cpp,dealer_dir,T,t,minimum,weights,ids,secret],log,env)
        found=re.findall(r'^share ([0-9.eE+-]+) s$',log.read_text(),re.M)
        if len(found)!=1:raise RuntimeError(f'Dealer {j}: missing VSS timer')
        return float(found[0])

    # Dealer 0 runs alone: it fixes the shared moduli every other dealer copies,
    # and it is the one that builds svole-<n+1> if the binary is missing. Launching
    # it concurrently would race on both.
    vss_start=time.perf_counter()
    dealer_times=[0.0]*n
    dealer_times[0]=run_dealer(0)
    workers=max(1,min(concurrency,n-1)) if n>1 else 0
    if workers:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures={executor.submit(run_dealer,j):j for j in range(1,n)}
            try:
                for future in as_completed(futures):
                    j=futures[future]
                    dealer_times[j]=future.result()
            except BaseException:
                for future in futures:future.cancel()
                raise
    vss_wall=time.perf_counter()-vss_start
    # Kept identical to the serial definition: sum of every dealer's Share timer.
    vss=sum(dealer_times)
    (out/'vss_seconds.txt').write_text(str(vss)+'\n')
    # Wall clock of the whole VSS phase. Equals vss when dealers run one at a time.
    (out/'vss_wall_seconds.txt').write_text(str(vss_wall)+'\n')
    print(f'VSS: sum={vss:.9f} s, wall={vss_wall:.9f} s, {workers} concurrent dealer(s) after dealer 1',flush=True)
    sid=(out/'dealer-0/parameters.txt').read_text().split()[0]
    plan=[('dkg',list(range(n)))]
    lines=[]
    for j,group in enumerate(sets.split(';')):
        selected=list(map(int,group.split(',')));name=f'sign_{j+1:02}'
        if len(set(selected))!=len(selected) or any(i<0 or i>=n for i in selected):raise ValueError('Invalid signer IDs')
        lines.append(f'{name} {group} message-{j+1}\n')
        if sum(ws[i] for i in selected)>=T and len(selected)>=2:plan.append((name,selected))
    (out/'sign_plan.txt').write_text(''.join(lines))
    offline={}
    for name,selected in plan:
        print(f'{name}: preparing fresh VSC material',flush=True)
        session=out/name;session.mkdir(mode=0o700)
        context={'degrees':[ws[i]*scale for i in selected],'h':(sum(ws[i] for i in selected)-T)*scale,'d0':d0,'q':Q,'sid':sid+'-'+name}
        (session/'context.json').write_text(json.dumps(context))
        offline[name]=run_preprocessing(mp,session,context,Path(__file__).with_name('preprocess_ch6.mpc'))['preprocessing_wall']
    for name,seconds in offline.items():
        (out/name/'offline_seconds.txt').write_text(str(seconds)+'\n')
    # Preserve the existing coarse VSC offline timing, without component timers.
    (out/'offline.json').write_text(json.dumps(offline,indent=2)+'\n')
    print('Starting DKG and signing tests',flush=True)
    subprocess.run([ch6,str(out)],check=True)
    # Independently verify public ECDSA outputs using only public values.
    sys.path.insert(0,str(ROOT/'gg18'))
    from run_sign import Q as order, G, add, multiply
    pub=tuple(int(x,16) for x in (out/'public_key.txt').read_text().split())
    for line in lines:
        name, group, message=line.split()
        selected=list(map(int,group.split(',')))
        if sum(ws[i] for i in selected)<T or len(selected)<2:continue
        sig=json.loads((out/name/'signature.json').read_text())
        if tuple(int(sig[k],16) for k in ('public_x','public_y'))!=pub:raise RuntimeError('Public key changed')
        digest=hashlib.sha256(message.encode()).hexdigest()
        if sig['digest']!=digest:raise RuntimeError('Wrong signed message')
        r,s=int(sig['r'],16),int(sig['s'],16)
        if not (0<r<order and 0<s<order):raise RuntimeError('Invalid signature scalar')
        inv=pow(s,-1,order)
        point=add(multiply(int(digest,16)*inv%order,G),multiply(r*inv%order,pub))
        if point is None or point[0]%order!=r:raise RuntimeError('Independent ECDSA verification failed')
    print(f'Results: {out / "results.csv"}')
if __name__=='__main__':
    os.umask(0o077);main()
