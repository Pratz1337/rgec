"""Matched sanitizer/coverage interventions in authentic full builds on Modal."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import modal


PROBE_END = r'''
try:
    evidence['native_bindings_sha256'] = save('native-bindings.json', open('/knownbits-scope-binding.json','rb').read())
    evidence['tool_sha256'] = {p: sha(open(p,'rb').read()) for p in config['tool_sha256']}
    assert evidence['tool_sha256'] == config['tool_sha256']
    save('native-proof.elf', open('/rgec-knownbits-proof','rb').read())
    save('installed-ISDOpcodes.h', open('/usr/local/include/llvm/CodeGen/ISDOpcodes.h','rb').read())
    evidence['arm_order'] = []; evidence['held_out'] = []
    for block in range(config['blocks']):
        arms=list(config['arms']); random.Random(evidence['seed']+block).shuffle(arms)
        evidence['arm_order'].append([a['name'] for a in arms])
        for arm in arms:
            config['flags']=arm['flags']
            modes=['original','native','census']
            index=next(i for i,a in enumerate(config['arms']) if a['name']==arm['name'])
            random.Random(evidence['seed']+100*(block+1)+index).shuffle(modes)
            rows={}
            for mode in modes:
                row,_=workflow('zlib-%s-b%d-%s'%(arm['name'],block,mode),mode)
                row.update(arm=arm['name'],flags=arm['flags'],block=block,order=modes.index(mode))
                rows[mode]=row; persist()
            equivalent(rows['native'],rows['original']); equivalent(rows['census'],rows['original'])
    source='/src/libfuzzer/FuzzerUtil.cpp'; source_body=open(source,'rb').read()
    save('FuzzerUtil.cpp.original',source_body); output=folder+'/FuzzerUtil.o'
    for arm in config['arms']:
        options=arm['flags']+['-stdlib=libc++','-std=c++11','-c','FuzzerUtil.cpp','-o',output]
        plan,_,error=execute(['/usr/local/bin/clang++']+options+['-###'],'/src/libfuzzer','fuzzer-'+arm['name']+'-plan',dict(ENV))
        commands=[shlex.split(line) for line in error.decode().splitlines() if '"-cc1"' in line]
        assert len(commands)==1; plan['arm']=arm['name']; evidence['plans'].append(plan)
        rows=[]
        for mode,binary in (('original','/usr/local/bin/clang'),('native','/rgec-knownbits-proof'),('census','/rgec-knownbits-scope')):
            label='fuzzer-'+arm['name']+'-'+mode
            env=dict(ENV,RGEC_KNOWNBITS_METRICS=folder+'/'+label+'.metrics')
            if mode=='census': env['RGEC_KNOWNBITS_CENSUS']=folder+'/'+label+'.census'
            os.chown(folder,65534,65534)
            row,_,_=execute([binary]+commands[0][1:],'/src/libfuzzer',label,env)
            row.update(arm=arm['name'],flags=arm['flags'],variant=mode,object_sha256=save(label+'.o',open(output,'rb').read()))
            rows.append(row); evidence['held_out'].append(row); persist()
        assert all(all(r[k]==rows[0][k] for k in ('returncode','stdout_sha256','stderr_sha256','object_sha256')) for r in rows)
    assert open(source,'rb').read()==source_body
    evidence['suite_complete']=True; result['returncode']=0
except BaseException:
    traceback.print_exc()
finally:
    persist(); sys.stdout.flush(); sys.stderr.flush()
    with tarfile.open(target+'/raw.tar.gz','w:gz') as archive:
        for directory,_,files in os.walk(folder):
            for name in sorted(files):
                path=directory+'/'+name
                if path==folder+'/FuzzerUtil.o': continue
                archive.add(path,arcname='raw/'+os.path.relpath(path,folder))
    for name in ('raw.tar.gz','stdout','stderr'): result[name+'_sha256']=sha(open(target+'/'+name,'rb').read())
    with open(target+'/result.json','w') as f: json.dump(result,f,indent=2)
sys.exit(result['returncode'])
'''


def sha(body): return hashlib.sha256(body).hexdigest()


def main(root):
    prior=Path('runs/rgec-modal-native-knownbits-cost-2026-10-11')
    sources=[Path('modal_rgec_sanitizer_cost.py'),Path('scripts/rgec_knownbits_scope_probe.py'),
        Path('src/unauthorized_channels/clang_knownbits_cost_census.cpp'),
        Path('src/unauthorized_channels/modal_recipient_entry.py')]
    if not root.exists():
        parent=json.loads((prior/'evidence.json').read_bytes())
        assert parent['sandbox']['returncode']==parent['sandbox']['cleanup_returncode']==0
        root.mkdir(parents=True)
        for p in sources: (root/p.name).write_bytes(p.read_bytes())
        for name in ('native-cost-build.py','native-cost-driver.py'):
            body=(prior/name).read_bytes(); assert sha(body)==parent['generated_sha256'][name]
            (root/name).write_bytes(body)
        flags=['-O1','-fno-omit-frame-pointer','-gline-tables-only','-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION']
        arms=[dict(name='asan-coverage',flags=flags+['-fsanitize=address','-fsanitize-address-use-after-scope','-fsanitize=fuzzer-no-link']),
            dict(name='coverage-only',flags=flags+['-fsanitize=fuzzer-no-link']),dict(name='plain',flags=flags)]
        tools=json.loads((prior/'raw/evidence.json').read_bytes())['tool_sha256']
        tools['/modal_recipient_entry.py']=sha((root/'modal_recipient_entry.py').read_bytes())
        assert tools['/clang_knownbits_cost_census.cpp']==sha((root/'clang_knownbits_cost_census.cpp').read_bytes())
        assert tools['/rgec-knownbits-driver']==sha((root/'native-cost-driver.py').read_bytes())
        config=dict(prefix=root.name,blocks=2,arms=arms,flags=arms[0]['flags'],native_sha256=tools['/usr/local/bin/clang'],tool_sha256=tools)
        (root/'knownbits-scope-config.json').write_bytes((json.dumps(config,indent=2)+'\n').encode())
        probe=(root/'rgec_knownbits_scope_probe.py').read_text().split('\ntry:\n')[0]
        probe=probe.replace("folder = '/workspace/knownbits-evidence'","folder = '/workspace/sanitizer-cost-evidence'")
        probe+="\nevidence['scope']='Matched sanitizer and coverage flag interventions on unchanged full zlib builds and unchanged C++ source. Native computations always execute. Only within-arm compiler controls require byte equivalence. Cost families are observational, not semantic certificates or cache savings.'\n"
        (root/'sanitizer-cost-probe.py').write_bytes((probe+'\n'+PROBE_END).encode())
        m=dict(platform='Modal',gpu=None,base_image_id=parent['sandbox']['image_id'],durable_volume=parent['durable_volume'],
            parent_manifest_sha256=sha((prior/'evidence.json').read_bytes()),
            source_sha256={p.as_posix():sha((root/p.name).read_bytes()) for p in sources},
            generated_sha256={n:sha((root/n).read_bytes()) for n in ('native-cost-build.py','native-cost-driver.py','sanitizer-cost-probe.py','knownbits-scope-config.json')},
            sandbox=None,universal_native_certificate=False,adaptive_noninterference_proved=False,substantial_novelty_established=False)
        (root/'evidence.json').write_bytes((json.dumps(m,indent=2)+'\n').encode())
    m=json.loads((root/'evidence.json').read_bytes())
    for p,digest in m['source_sha256'].items(): assert sha((root/Path(p).name).read_bytes())==digest
    for p,digest in m['generated_sha256'].items(): assert sha((root/p).read_bytes())==digest
    def persist(): (root/'evidence.json').write_bytes((json.dumps(m,indent=2)+'\n').encode())
    volume=modal.Volume.from_name(m['durable_volume']); app=modal.App('rgec-sanitizer-cost-intervention')
    with modal.enable_output(),app.run(detach=True):
        if m['sandbox'] is None:
            image=modal.Image.from_id(m['base_image_id'])
            for name in ('sanitizer-cost-probe.py','knownbits-scope-config.json'):
                image=image.add_local_file(str(root/name),'/'+name,copy=True)
            worker=modal.Sandbox.create('/usr/bin/python3','-I','/sanitizer-cost-probe.py',app=app,image=image,
                cpu=2,memory=8192,timeout=2400,block_network=True,volumes={'/retained':volume})
            m['sandbox']=dict(id=worker.object_id,image_id=image.object_id); persist(); print('Sanitizer cost study',worker.object_id,flush=True)
        else: worker=modal.Sandbox.from_id(m['sandbox']['id'])
        if 'returncode' not in m['sandbox']:
            worker.wait(); m['sandbox']['cleanup_returncode']=worker.returncode; persist()
            for name in ('result.json','stdout','stderr','raw.tar.gz'):
                (root/name).write_bytes(b''.join(volume.read_file(root.name+'/'+name)))
            result=json.loads((root/'result.json').read_bytes()); m['sandbox']['returncode']=result['returncode']; persist()
            for name in ('stdout','stderr','raw.tar.gz'): assert sha((root/name).read_bytes())==result[name+'_sha256']
            with tarfile.open(root/'raw.tar.gz') as archive:
                members=archive.getmembers(); assert len({p.name for p in members})==len(members)
                for member in members:
                    parts=Path(member.name).parts; assert member.isfile() and parts[0]=='raw' and '..' not in parts
                    p=root/member.name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(archive.extractfile(member).read())
        assert m['sandbox']['returncode']==m['sandbox']['cleanup_returncode']==0
        print('Matched full workloads and native cost records retained',flush=True)


if __name__=='__main__': main(Path(sys.argv[1]))
