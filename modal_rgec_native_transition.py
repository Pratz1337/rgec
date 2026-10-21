"""Real full-build entry capture and strict native model checking, on Modal only."""
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
        ('/usr/local/bin/clang','/rgec-native-entry-proof','/rgec-knownbits-scope','/clang_native_entry_capture.cpp','/rgec-knownbits-driver')}
    assert evidence['tool_sha256']['/usr/local/bin/clang'] == config['native_sha256']
    save('native-proof.elf', open('/rgec-native-entry-proof','rb').read())
    for relative in ('llvm/CodeGen/ISDOpcodes.h','llvm/CodeGen/SelectionDAGNodes.h'):
        save('installed-'+relative.replace('/','__'),open('/usr/local/include/'+relative,'rb').read())
    reference, _ = workflow('original-control','original')
    proof, _ = workflow('proof-control','native'); equivalent(proof, reference)
    capture, _ = workflow('captured-native','capture'); equivalent(capture, reference)
    source='/src/libfuzzer/FuzzerUtil.cpp'; source_body=open(source,'rb').read()
    save('FuzzerUtil.cpp.original',source_body); output=folder+'/FuzzerUtil.o'
    options=config['flags']+['-stdlib=libc++','-std=c++11','-c','FuzzerUtil.cpp','-o',output]
    plan, _, error=execute(['/usr/local/bin/clang++']+options+['-###'],'/src/libfuzzer','fuzzer-plan',dict(ENV))
    commands=[shlex.split(line) for line in error.decode().splitlines() if '"-cc1"' in line]
    assert len(commands)==1; evidence['plans'].append(plan); evidence['held_out']=[]
    for mode,binary in (('original','/usr/local/bin/clang'),('native','/rgec-native-entry-proof'),('capture','/rgec-knownbits-scope')):
        label='fuzzer-'+mode; env=dict(ENV,RGEC_KNOWNBITS_METRICS=folder+'/'+label+'.metrics')
        if mode=='capture': env['RGEC_NATIVE_CAPTURE']=folder+'/FuzzerUtil.entry'
        os.chown(folder,65534,65534)
        row, _, _=execute([binary]+commands[0][1:],'/src/libfuzzer',label,env)
        row.update(variant=mode,object_sha256=save(label+'.o',open(output,'rb').read()))
        evidence['held_out'].append(row); persist()
    reference=evidence['held_out'][0]
    assert all(all(r[k]==reference[k] for k in ('returncode','stdout_sha256','stderr_sha256','object_sha256')) for r in evidence['held_out'])
    assert open(source,'rb').read()==source_body
    entries=[]
    for directory, _, files in os.walk(folder):
        for name in sorted(files):
            if not name.endswith('.entry'): continue
            path=directory+'/'+name; row=json.load(open(path)); row['path']=os.path.relpath(path,folder)
            row['files']={suffix:sha(open(path+suffix,'rb').read()) for suffix in ('','.maps','.memory','.after')}
            entries.append(row)
    assert entries, 'No selected native entry was exercised'
    evidence['native_entries']=entries; evidence['suite_complete']=True; result['returncode']=0
except BaseException:
    traceback.print_exc()
finally:
    persist(); sys.stdout.flush(); sys.stderr.flush()
    with tarfile.open(target+'/raw.tar.gz','w:gz') as archive:
        for directory, _, files in os.walk(folder):
            for name in sorted(files):
                path=directory+'/'+name
                if path==folder+'/FuzzerUtil.o': continue
                archive.add(path,arcname='raw/'+os.path.relpath(path,folder))
    for name in ('raw.tar.gz','stdout','stderr'): result[name+'_sha256']=sha(open(target+'/'+name,'rb').read())
    with open(target+'/result.json','w') as f: json.dump(result,f,indent=2)
sys.exit(result['returncode'])
'''

MODEL_WORKER = r'''
import hashlib,json,os,pathlib,shutil,subprocess,sys,tarfile,traceback
c=json.load(open('/config.json')); prefix=c['prefix']; root=pathlib.Path('/native-check');root.mkdir()
target=pathlib.Path('/retained')/prefix/'native-model';target.mkdir()
r={'returncode':1,'native_compiler_actions':0,'universal_native_certificate':False}
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
try:
 archive_path=pathlib.Path('/retained')/prefix/'raw.tar.gz'
 assert sha(archive_path)==c['archive_sha256'] and sha('/checker.py')==c['checker_sha256']
 with tarfile.open(archive_path) as a:
  members=a.getmembers();assert len({m.name for m in members})==len(members)
  for m in members:
   parts=pathlib.Path(m.name).parts;assert m.isfile() and parts[0]=='raw' and '..' not in parts
   if m.name!='raw/native-proof.elf' and not any(m.name.endswith(s) for s in ('.entry','.entry.maps','.entry.memory','.entry.after')):continue
   output=root/m.name;output.parent.mkdir(parents=True,exist_ok=True)
   with output.open('wb') as f:shutil.copyfileobj(a.extractfile(m),f)
 assert sha(root/'raw/native-proof.elf')==c['proof_elf_sha256']
 with (target/'stdout').open('wb') as out,(target/'stderr').open('wb') as err:
  r['returncode']=subprocess.call([sys.executable,'-I','/checker.py',str(root/'raw/native-proof.elf'),str(root/'raw'),str(target/'native-transition-check.json')],stdout=out,stderr=err)
 if (target/'native-transition-check.json').exists():r['check_sha256']=sha(target/'native-transition-check.json')
except BaseException:
 r['returncode']=1
 with (target/'stderr').open('a') as f:traceback.print_exc(file=f)
(target/'result.json').write_text(json.dumps(r,indent=2)+'\n')
sys.exit(r['returncode'])
'''


def sha(data): return hashlib.sha256(data).hexdigest()


def collect(volume, remote, root, names):
    for name in names: (root/name).write_bytes(b''.join(volume.read_file(remote+'/'+name)))


def main(root, arithmetic=False):
    prior=Path('runs/rgec-modal-native-region-capsule-2026-10-10')
    old=Path('runs/rgec-modal-native-stream-admission-2026-10-09-v27/native-build.py')
    sources=[Path('modal_rgec_native_transition.py'),Path('src/unauthorized_channels/clang_native_entry_capture.cpp'),
        Path('scripts/check_rgec_native_transition.py'),Path('scripts/rgec_knownbits_scope_probe.py'),
        Path('scripts/rgec_knownbits_driver.py'),Path('src/unauthorized_channels/modal_recipient_entry.py'),
        Path('modal_rgec_knownbits_scope.py')]
    manifest=root/'evidence.json'
    if not root.exists():
        root.mkdir(parents=True)
        for p in sources:(root/p.name).write_bytes(p.read_bytes())
        build=old.read_text();needle="command+=['/rgec-backend.cpp','-o','/rgec-backend','-Wl,--wrap='+symbol]"
        assert build.count(needle)==1
        build=build.replace(needle,"command+=['/rgec-backend.cpp','/native-entry.o','-o','/rgec-knownbits-scope','-Wl,--wrap='+symbol]")
        symbol='_ZNK4llvm12SelectionDAG16computeKnownBitsENS_7SDValueERNS_9KnownBitsERKNS_5APIntEj'
        build=build.replace("command+=['-Wl,--start-group']","command+=['-Wl,--wrap="+symbol+"']\ncommand+=['-Wl,--start-group']")
        define="'-DRGEC_ARITHMETIC_CAPTURE'," if arithmetic else ''
        build="import subprocess,shutil\nsubprocess.check_call(['/usr/local/bin/clang++','-O2','-std=c++14','-fno-rtti','-I/usr/local/include',"+define+"'-c','/clang_native_entry_capture.cpp','-o','/native-entry.o'])\n"+build+"\nshutil.copy2('/rgec-knownbits-scope','/rgec-native-entry-proof')\n"+BINDINGS
        (root/'native-entry-build.py').write_text(build,encoding='utf-8')
        driver=(root/'rgec_knownbits_driver.py').read_text()
        line="binary = '/usr/local/bin/clang' if mode == 'original' else '/rgec-knownbits-scope'"
        assert driver.count(line)==1
        driver=driver.replace(line,"binary = '/usr/local/bin/clang' if mode == 'original' else '/rgec-native-entry-proof' if mode == 'native' else '/rgec-knownbits-scope'")
        driver=driver.replace("before = resource.getrusage(resource.RUSAGE_CHILDREN)","if mode == 'capture' and os.path.basename(output) in ('deflate.o','inffast.o','infback.o'):\n    env['RGEC_NATIVE_CAPTURE'] = folder + '/' + label + '.entry'\nbefore = resource.getrusage(resource.RUSAGE_CHILDREN)")
        (root/'native-entry-driver.py').write_bytes(driver.encode('utf-8'))
        probe=(root/'rgec_knownbits_scope_probe.py').read_text().split('\ntry:\n')[0]
        probe=probe.replace("folder = '/workspace/knownbits-evidence'","folder = '/workspace/native-entry-evidence'")
        probe=probe.replace("scope='Source-derived scalar structural scope, trusted same-binary native packets, genuine complete zlib builds and upstream tests, real repository round trips and held-out C++ compilation. Entry projection precedes lookup. Finite shadow checks are not native semantic certificates; allocator/fault/resource/physical-observer equivalence is not established.'", "scope='Actual native entry snapshots during unchanged full builds. No cached answer or substituted analysis. Native machine-model checking is separate; universal native and exceptional/resource equivalence remain unestablished.'")
        (root/'native-entry-probe.py').write_text(probe+'\n'+PROBE_END,encoding='utf-8')
        config=dict(prefix=root.name,blocks=0,capture_family='ADD64(SRL,Constant)' if arithmetic else 'TRUNCATE32',native_sha256=json.loads((prior/'region-capsule-config.json').read_bytes())['native_sha256'],
            flags=['-O1','-fno-omit-frame-pointer','-gline-tables-only','-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION',
                '-fsanitize=address','-fsanitize-address-use-after-scope','-fsanitize=fuzzer-no-link'])
        (root/'knownbits-scope-config.json').write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
        (root/'native-model-worker.py').write_text(MODEL_WORKER,encoding='utf-8')
        m=dict(platform='Modal',gpu=None,base_image_id=json.loads((prior/'evidence.json').read_bytes())['sandbox']['image_id'],
            durable_volume=json.loads((prior/'evidence.json').read_bytes())['durable_volume'],
            source_sha256={p.as_posix():sha((root/p.name).read_bytes()) for p in sources},
            generated_sha256={name:sha((root/name).read_bytes()) for name in ('native-entry-build.py','native-entry-driver.py','native-entry-probe.py','knownbits-scope-config.json','native-model-worker.py')},
            capture=None,native_model=None,universal_native_certificate=False,adaptive_noninterference_proved=False,substantial_novelty_established=False)
        manifest.write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8')
    m=json.loads(manifest.read_bytes())
    for p,digest in m['source_sha256'].items():assert sha((root/Path(p).name).read_bytes())==digest
    for p,digest in m['generated_sha256'].items():assert sha((root/p).read_bytes())==digest
    def persist():manifest.write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8')
    volume=modal.Volume.from_name(m['durable_volume']);app=modal.App('rgec-native-transition-construction')
    with modal.enable_output(),app.run(detach=True):
        if m['capture'] is None:
            image=modal.Image.from_id(m['base_image_id'])
            for local,remote in (('clang_native_entry_capture.cpp','clang_native_entry_capture.cpp'),('native-entry-build.py','native-entry-build.py'),
                ('native-entry-driver.py','rgec_knownbits_driver.py'),('native-entry-probe.py','native-entry-probe.py'),
                ('knownbits-scope-config.json','knownbits-scope-config.json'),('modal_recipient_entry.py','modal_recipient_entry.py')):
                image=image.add_local_file(str(root/local),'/'+remote,copy=True)
            image=image.run_commands('/usr/bin/python3 -I /native-entry-build.py','cp /rgec_knownbits_driver.py /rgec-knownbits-driver && chmod 555 /rgec-knownbits-driver')
            worker=modal.Sandbox.create('/usr/bin/python3','-I','/native-entry-probe.py',app=app,image=image,
                cpu=2,memory=8192,timeout=2400,block_network=True,volumes={'/retained':volume})
            m['capture']=dict(id=worker.object_id,image_id=image.object_id);persist();print('Genuine native entry capture',worker.object_id,flush=True)
        else:worker=modal.Sandbox.from_id(m['capture']['id'])
        if 'returncode' not in m['capture']:
            worker.wait();m['capture']['cleanup_returncode']=worker.returncode;persist()
            collect(volume,root.name,root,('result.json','stdout','stderr','raw.tar.gz'))
            result=json.loads((root/'result.json').read_bytes());m['capture']['returncode']=result['returncode'];persist()
            for name in ('stdout','stderr','raw.tar.gz'):assert sha((root/name).read_bytes())==result[name+'_sha256']
            with tarfile.open(root/'raw.tar.gz') as archive:
                for member in archive.getmembers():
                    parts=Path(member.name).parts;assert member.isfile() and parts[0]=='raw' and '..' not in parts
                    p=root/member.name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(archive.extractfile(member).read())
            assert result['returncode']==worker.returncode==0
        assert m['capture']['returncode']==m['capture']['cleanup_returncode']==0
        folder=root/'native-model';folder.mkdir(exist_ok=True)
        if m['native_model'] is None:
            raw=json.loads((root/'raw/evidence.json').read_bytes())
            config=dict(prefix=root.name,archive_sha256=sha((root/'raw.tar.gz').read_bytes()),
                checker_sha256=sha((root/'check_rgec_native_transition.py').read_bytes()),proof_elf_sha256=raw['tool_sha256']['/rgec-native-entry-proof'])
            (folder/'config.json').write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
            image=modal.Image.debian_slim(python_version='3.12').pip_install('angr==9.2.223')
            for local,remote in ((root/'check_rgec_native_transition.py','/checker.py'),(root/'native-model-worker.py','/worker.py'),(folder/'config.json','/config.json')):
                image=image.add_local_file(str(local),remote,copy=True)
            model=modal.Sandbox.create('python3','-I','/worker.py',app=app,image=image,
                cpu=2,memory=16384,timeout=2400,block_network=True,volumes={'/retained':volume})
            m['native_model']=dict(id=model.object_id,image_id=image.object_id);persist();print('Native machine-model checker',model.object_id,flush=True)
        else:model=modal.Sandbox.from_id(m['native_model']['id'])
        model.wait();m['native_model']['cleanup_returncode']=model.returncode;persist()
        collect(volume,root.name+'/native-model',folder,('result.json','stdout','stderr'))
        result=json.loads((folder/'result.json').read_bytes());m['native_model']['returncode']=result['returncode'];persist()
        if 'check_sha256' in result:
            collect(volume,root.name+'/native-model',folder,('native-transition-check.json',))
            assert sha((folder/'native-transition-check.json').read_bytes())==result['check_sha256']
            m['native_model']['check_sha256']=result['check_sha256'];persist()
        assert result['returncode']==model.returncode==0, result
        print('Native construction evidence collected',flush=True)


if __name__=='__main__':main(Path(sys.argv[1]),len(sys.argv)>2 and sys.argv[2]=='arithmetic')
