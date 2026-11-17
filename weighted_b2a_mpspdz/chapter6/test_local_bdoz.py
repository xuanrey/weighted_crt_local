"""Cleartext execution harness for MPC source + local BDOZ + real C++ VSC.
Does NOT test MASCOT compilation, networking or malicious security.
"""
from pathlib import Path
from types import SimpleNamespace
import secrets
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root/'chapter5'))
from local_bdoz import attach_local_bdoz
Q = 115792089237316195423570985008687907852837564279074904382605163141518161494337
class Sint:
    get_random_bit = staticmethod(lambda: secrets.randbits(1))
    get_random = staticmethod(lambda: secrets.randbelow(Q))
    Array = staticmethod(lambda n: [0]*n)
def for_range(n):
    def run(f):
        for i in range(n): f(i)
    return run
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    binary = tmp/'test'
    subprocess.run(['g++','-std=c++17','-O2',str(root/'chapter6/test_local_bdoz.cpp'),
                    '-lcrypto','-lgmpxx','-lgmp','-o',str(binary)],check=True)
    for index,(weights,T,t) in enumerate([([2,2,2,2],5,3),([196,201,232,220],512,256),([476,523,515,602],896,640)]):
        scale=max((10+min(weights)-1)//min(weights),(256+T-t-1)//(T-t))
        context={'degrees':[w*scale for w in weights],'h':(sum(weights)-T)*scale,'d0':(T-t)*scale,'q':str(Q),'sid':'test'}
        for chapter in ('chapter5','chapter6'):
            pre=tmp/f'{index}-{chapter}';pre.mkdir()
            outputs=[[] for _ in weights]
            def emit(i,fmt,*values):outputs[i].append(fmt % (*values[:-1], values[-1] % Q) + '\n')
            sys.modules['Compiler']=SimpleNamespace()
            sys.modules['Compiler.types']=SimpleNamespace(sint=Sint)
            sys.modules['Compiler.library']=SimpleNamespace(print_ln_to=emit,check_point=lambda:None,start_timer=lambda _:None,stop_timer=lambda _:None,for_range=for_range)
            program=SimpleNamespace(args=['test',','.join(map(str,context['degrees'])),str(context['h']),str(context['d0'])],options=SimpleNamespace(prime=Q))
            source=root/chapter/f'preprocess_ch{chapter[-1]}.mpc'
            exec(compile(source.read_text().replace('.reveal_to(i)',''),str(source),'exec'),{'program':program})
            for i,lines in enumerate(outputs):(pre/f'role-{i}.txt').write_text(''.join(lines))
            before=[(pre/f'role-{i}.txt').read_text() for i in range(len(weights))]
            attach_local_bdoz(pre,context)
            for i,text in enumerate(before):assert (pre/f'role-{i}.txt').read_text().startswith(text)
            try:attach_local_bdoz(pre,context)
            except ValueError:pass
            else:raise AssertionError('Reauthentication accepted')
            (pre/'READY').write_text(f'test {Q}\n')
            subprocess.run([str(binary),str(pre),','.join(map(str,weights)),str(T),str(t)],check=True)
print('Six cleartext-source/C++ integration cases passed; not a MASCOT run.')
