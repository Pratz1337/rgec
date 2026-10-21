"""Native cost/answer census during unchanged full workloads, on Modal only."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import modal
from modal_rgec_knownbits_scope import BINDINGS


PROBE_END = r'''
try:
    evidence['native_bindings_sha256'] = save('native-bindings.json', open('/knownbits-scope-binding.json','rb').read())
    evidence['tool_sha256'] = {p: sha(open(p,'rb').read()) for p in
        ('/usr/local/bin/clang','/rgec-knownbits-proof','/rgec-knownbits-scope','/clang_knownbits_cost_census.cpp','/rgec-knownbits-driver')}
    assert evidence['tool_sha256']['/usr/local/bin/clang'] == config['native_sha256']
    save('native-proof.elf', open('/rgec-knownbits-proof','rb').read())
    save('installed-ISDOpcodes.h',open('/usr/local/include/llvm/CodeGen/ISDOpcodes.h','rb').read())
    for block in range(config['blocks']):
        modes=['original','native','census']; random.Random(evidence['seed']+block).shuffle(modes)
        rows={}
        for mode in modes:
            row,_=workflow('zlib-b%d-%s'%(block,mode),mode)
            row.update(block=block,order=modes.index(mode)); rows[mode]=row; persist()
        equivalent(rows['native'],rows['original']); equivalent(rows['census'],rows['original'])
    source='/src/libfuzzer/FuzzerUtil.cpp'; source_body=open(source,'rb').read()
    save('FuzzerUtil.cpp.original',source_body); output=folder+'/FuzzerUtil.o'
    options=config['flags']+['-stdlib=libc++','-std=c++11','-c','FuzzerUtil.cpp','-o',output]
    plan,_,error=execute(['/usr/local/bin/clang++']+options+['-###'],'/src/libfuzzer','fuzzer-plan',dict(ENV))
    commands=[shlex.split(line) for line in error.decode().splitlines() if '"-cc1"' in line]
    assert len(commands)==1; evidence['plans'].append(plan); evidence['held_out']=[]
    for mode,binary in (('original','/usr/local/bin/clang'),('native','/rgec-knownbits-proof'),('census','/rgec-knownbits-scope')):
        label='fuzzer-'+mode; env=dict(ENV,RGEC_KNOWNBITS_METRICS=folder+'/'+label+'.metrics')
        if mode=='census': env['RGEC_KNOWNBITS_CENSUS']=folder+'/'+label+'.census'
        os.chown(folder,65534,65534)
        row,_,_=execute([binary]+commands[0][1:],'/src/libfuzzer',label,env)
        row.update(variant=mode,object_sha256=save(label+'.o',open(output,'rb').read()))
        evidence['held_out'].append(row); persist()
    reference=evidence['held_out'][0]
    assert all(all(r[k]==reference[k] for k in ('returncode','stdout_sha256','stderr_sha256','object_sha256')) for r in evidence['held_out'])
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
    prior=Path('runs/rgec-modal-native-region-capsule-2026-10-10')
    old=Path('runs/rgec-modal-native-stream-admission-2026-10-09-v27/native-build.py')
    sources=[Path('modal_rgec_knownbits_cost.py'),old,Path('src/unauthorized_channels/clang_knownbits_cost_census.cpp'),
        Path('scripts/rgec_knownbits_scope_probe.py'),Path('scripts/rgec_knownbits_driver.py'),
        Path('src/unauthorized_channels/modal_recipient_entry.py'),Path('modal_rgec_knownbits_scope.py')]
    if not root.exists():
        root.mkdir(parents=True)
        for p in sources:(root/p.name).write_bytes(p.read_bytes())
        build=old.read_text(); needle="command+=['/rgec-backend.cpp','-o','/rgec-backend','-Wl,--wrap='+symbol]"
        assert build.count(needle)==1
        build=build.replace(needle,"command+=['/rgec-backend.cpp','/cost-census.o','-o','/rgec-knownbits-scope','-Wl,--wrap='+symbol]")
        symbol='_ZNK4llvm12SelectionDAG16computeKnownBitsENS_7SDValueERNS_9KnownBitsERKNS_5APIntEj'
        build=build.replace("command+=['-Wl,--start-group']","command+=['-Wl,--wrap="+symbol+"']\ncommand+=['-Wl,--start-group']")
        build="import subprocess,shutil\nsubprocess.check_call(['/usr/local/bin/clang++','-O2','-std=c++14','-fno-rtti','-I/usr/local/include','-c','/clang_knownbits_cost_census.cpp','-o','/cost-census.o'])\n"+build+"\nshutil.copy2('/rgec-knownbits-scope','/rgec-knownbits-proof')\n"+BINDINGS
        (root/'native-cost-build.py').write_bytes(build.encode())
        driver=(root/'rgec_knownbits_driver.py').read_text()
        needle="binary = '/usr/local/bin/clang' if mode == 'original' else '/rgec-knownbits-scope'"
        assert driver.count(needle)==1
        driver=driver.replace(needle,"binary = '/usr/local/bin/clang' if mode == 'original' else '/rgec-knownbits-proof' if mode == 'native' else '/rgec-knownbits-scope'")
        driver=driver.replace("before = resource.getrusage(resource.RUSAGE_CHILDREN)","if mode == 'census': env['RGEC_KNOWNBITS_CENSUS'] = folder + '/' + label + '.census'\nbefore = resource.getrusage(resource.RUSAGE_CHILDREN)")
        (root/'native-cost-driver.py').write_bytes(driver.encode())
        probe=(root/'rgec_knownbits_scope_probe.py').read_text().split('\ntry:\n')[0]
        probe=probe.replace("folder = '/workspace/knownbits-evidence'","folder = '/workspace/native-cost-evidence'")
        probe += "\nevidence['scope']='Observational native call cost and answer census during unchanged full workloads. Native computation is never skipped. RDTSCP samples include timer overhead and native calls; same-CPU samples are not CPU-time or complete-cache-utility estimates. No semantic/adaptive certificate or novelty follows from this census.'\n"
        (root/'native-cost-probe.py').write_bytes((probe+'\n'+PROBE_END).encode())
        config=dict(prefix=root.name,blocks=2,native_sha256=json.loads((prior/'region-capsule-config.json').read_bytes())['native_sha256'],
            flags=['-O1','-fno-omit-frame-pointer','-gline-tables-only','-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION',
                '-fsanitize=address','-fsanitize-address-use-after-scope','-fsanitize=fuzzer-no-link'])
        (root/'knownbits-scope-config.json').write_bytes((json.dumps(config,indent=2)+'\n').encode())
        m=dict(platform='Modal',gpu=None,base_image_id=json.loads((prior/'evidence.json').read_bytes())['sandbox']['image_id'],
            durable_volume=json.loads((prior/'evidence.json').read_bytes())['durable_volume'],
            source_sha256={p.as_posix():sha((root/p.name).read_bytes()) for p in sources},
            generated_sha256={p:sha((root/p).read_bytes()) for p in ('native-cost-build.py','native-cost-driver.py','native-cost-probe.py','knownbits-scope-config.json')},
            sandbox=None,universal_native_certificate=False,adaptive_noninterference_proved=False,substantial_novelty_established=False)
        (root/'evidence.json').write_bytes((json.dumps(m,indent=2)+'\n').encode())
    m=json.loads((root/'evidence.json').read_bytes())
    for p,digest in m['source_sha256'].items():assert sha((root/Path(p).name).read_bytes())==digest
    for p,digest in m['generated_sha256'].items():assert sha((root/p).read_bytes())==digest
    def persist():(root/'evidence.json').write_bytes((json.dumps(m,indent=2)+'\n').encode())
    volume=modal.Volume.from_name(m['durable_volume']); app=modal.App('rgec-native-cost-census')
    with modal.enable_output(),app.run(detach=True):
        if m['sandbox'] is None:
            image=modal.Image.from_id(m['base_image_id'])
            for local,remote in (('clang_knownbits_cost_census.cpp','clang_knownbits_cost_census.cpp'),('native-cost-build.py','native-cost-build.py'),
                    ('native-cost-driver.py','rgec_knownbits_driver.py'),('native-cost-probe.py','native-cost-probe.py'),
                    ('knownbits-scope-config.json','knownbits-scope-config.json'),('modal_recipient_entry.py','modal_recipient_entry.py')):
                image=image.add_local_file(str(root/local),'/'+remote,copy=True)
            image=image.run_commands('/usr/bin/python3 -I /native-cost-build.py','cp /rgec_knownbits_driver.py /rgec-knownbits-driver && chmod 555 /rgec-knownbits-driver')
            worker=modal.Sandbox.create('/usr/bin/python3','-I','/native-cost-probe.py',app=app,image=image,
                cpu=2,memory=8192,timeout=2400,block_network=True,volumes={'/retained':volume})
            m['sandbox']=dict(id=worker.object_id,image_id=image.object_id);persist();print('Native cost census',worker.object_id,flush=True)
        else:worker=modal.Sandbox.from_id(m['sandbox']['id'])
        if 'returncode' not in m['sandbox']:
            worker.wait();m['sandbox']['cleanup_returncode']=worker.returncode;persist()
            for name in ('result.json','stdout','stderr','raw.tar.gz'):
                (root/name).write_bytes(b''.join(volume.read_file(root.name+'/'+name)))
            r=json.loads((root/'result.json').read_bytes());m['sandbox']['returncode']=r['returncode'];persist()
            for name in ('stdout','stderr','raw.tar.gz'):assert sha((root/name).read_bytes())==r[name+'_sha256']
            with tarfile.open(root/'raw.tar.gz') as archive:
                members=archive.getmembers();assert len({p.name for p in members})==len(members)
                for member in members:
                    parts=Path(member.name).parts;assert member.isfile() and parts[0]=='raw' and '..' not in parts
                    p=root/member.name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(archive.extractfile(member).read())
        assert m['sandbox']['returncode']==m['sandbox']['cleanup_returncode']==0
        print('Full native workflows and cost census retained',flush=True)


if __name__=='__main__':main(Path(sys.argv[1]))
