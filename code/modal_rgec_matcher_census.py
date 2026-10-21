"""Build and test an authentic native matcher invocation census on Modal."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import modal


PATCH_BINDINGS = r'''
# Calls inside LLVM's object can be resolved before --wrap applies. Instrument
# only the four decoded call instructions in SelectCodeCommon, retaining every
# original predicate as the wrapper's __real target.
import hashlib,json,re,struct
path='/rgec-matcher-census'; body=open(path,'rb').read(); original=body
assert body[:7]==b'\x7fELF\x02\x01\x01'
h=struct.unpack_from('<HHIQQQIHHHHHH',body,16)
assert h[0:2]==(2,62) and h[8]==56
symbols={}
for line in subprocess.check_output(['/usr/bin/nm','-n','-S','--defined-only',path]).decode().splitlines():
 f=line.split()
 if len(f)==4: symbols[f[3]]=(int(f[0],16),int(f[1],16))
select='_ZN4llvm16SelectionDAGISel16SelectCodeCommonEPNS_6SDNodeEPKhj'
start,size=symbols[select]
disassembly=subprocess.check_output(['/usr/bin/objdump','-d','--start-address=%d'%start,'--stop-address=%d'%(start+size),path]).decode()
names=['_ZNK4llvm16SelectionDAGISel12CheckAndMaskENS_7SDValueEPNS_14ConstantSDNodeEl',
 '_ZNK4llvm16SelectionDAGISel11CheckOrMaskENS_7SDValueEPNS_14ConstantSDNodeEl']
targets={symbols[n][0]:('__wrap_'+n,symbols['__wrap_'+n][0]) for n in names}
changes=[]
for line in disassembly.splitlines():
 match=re.match(r'^\s*([0-9a-f]+):.*\bcallq\s+([0-9a-f]+)\s',line)
 if not match or int(match.group(2),16) not in targets: continue
 pc,dest=int(match.group(1),16),int(match.group(2),16); name,new=targets[dest]
 positions=[]
 for i in range(h[9]):
  kind,flags,offset,address,_,filesize,_,_=struct.unpack_from('<II6Q',body,h[4]+i*56)
  if kind==1 and address<=pc and pc+5<=address+filesize:
   assert flags & 1 and not flags & 2
   positions.append(offset+pc-address)
 offset,=positions; before=body[offset:offset+5]
 assert before[0]==0xe8 and pc+5+struct.unpack('<i',before[1:])[0]==dest
 after=b'\xe8'+struct.pack('<i',new-pc-5)
 body=body[:offset]+after+body[offset+5:]
 changes.append(dict(pc=pc,file_offset=offset,old_target=dest,new_target=new,symbol=name,
  original_hex=before.hex(),patched_hex=after.hex()))
assert len(changes)==4 and all(sum(c['symbol']=='__wrap_'+n for c in changes)==2 for n in names)
assert sum(a!=b for a,b in zip(original,body))<=16 and len(original)==len(body)
with open(path,'wb') as f: f.write(body)
with open('/matcher-census-binding.json','w') as f:
 json.dump(dict(unpatched_sha256=hashlib.sha256(original).hexdigest(),
  patched_sha256=hashlib.sha256(body).hexdigest(),select_symbol=select,
  select_address=start,select_size=size,changes=changes),f,indent=2)
'''


def sha(data): return hashlib.sha256(data).hexdigest()


def main(root):
    prior_root = Path('runs/rgec-modal-native-region-capsule-2026-10-10')
    prior = json.loads((prior_root / 'evidence.json').read_bytes())
    assert prior['sandbox']['returncode'] == prior['sandbox']['cleanup_returncode'] == 0
    v27 = Path('runs/rgec-modal-native-stream-admission-2026-10-09-v27')
    paths = [Path('modal_rgec_matcher_census.py'), Path('scripts/rgec_matcher_census_probe.py'),
        Path('src/unauthorized_channels/clang_matcher_census.cpp'), Path('src/unauthorized_channels/modal_recipient_entry.py')]
    manifest = root / 'evidence.json'
    if not root.exists():
        root.mkdir(parents=True)
        for path in paths: (root / path.name).write_bytes(path.read_bytes())
        original = (v27 / 'native-build.py').read_text()
        old = "command+=['/rgec-backend.cpp','-o','/rgec-backend','-Wl,--wrap='+symbol]"
        assert original.count(old) == 1
        build = original.replace(old, "command+=['/rgec-backend.cpp','/clang_matcher_census.cpp','-o','/rgec-matcher-census','-Wl,--wrap='+symbol]")
        needle = "command+=['-Wl,--start-group']"
        assert build.count(needle) == 1
        wraps = [
            '_ZN4llvm16SelectionDAGISel16SelectCodeCommonEPNS_6SDNodeEPKhj',
            '_ZNK4llvm16SelectionDAGISel12CheckAndMaskENS_7SDValueEPNS_14ConstantSDNodeEl',
            '_ZNK4llvm16SelectionDAGISel11CheckOrMaskENS_7SDValueEPNS_14ConstantSDNodeEl']
        build = build.replace(needle, 'command+=' + repr(['-Wl,--wrap=' + name for name in wraps]) + '\n' + needle)
        build += '\n' + PATCH_BINDINGS
        (root / 'native-census-build.py').write_text(build, encoding='utf-8')
        config = dict(prefix=root.name, native_sha256=json.loads((prior_root / 'region-capsule-config.json').read_bytes())['native_sha256'],
            backend_source_sha256=sha((v27 / 'clang_backend_continuation.cpp').read_bytes()),
            census_source_sha256=sha((root / 'clang_matcher_census.cpp').read_bytes()))
        (root / 'matcher-census-config.json').write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8')
        m = dict(platform='Modal', cpu=2, memory_mib=8192, gpu=None,
            base_image_id=prior['sandbox']['image_id'], durable_volume=prior['durable_volume'],
            source_sha256={p.as_posix(): sha((root / p.name).read_bytes()) for p in paths},
            original_build_sha256=sha((v27 / 'native-build.py').read_bytes()),
            build_sha256=sha((root / 'native-census-build.py').read_bytes()),
            config_sha256=sha((root / 'matcher-census-config.json').read_bytes()),
            native_mask_call_binding='four validated direct call sites instrumented after native linking',
            sandbox=None, native_census_builds=1, runtime_network_blocked=True,
            complete_closure_certified=False, substantial_novelty_established=False)
        manifest.write_text(json.dumps(m, indent=2) + '\n', encoding='utf-8')
    m = json.loads(manifest.read_bytes())
    for path, expected in m['source_sha256'].items(): assert sha((root / Path(path).name).read_bytes()) == expected
    assert sha((root / 'native-census-build.py').read_bytes()) == m['build_sha256']
    assert sha((root / 'matcher-census-config.json').read_bytes()) == m['config_sha256']
    def persist(): manifest.write_text(json.dumps(m, indent=2) + '\n', encoding='utf-8')
    volume = modal.Volume.from_name(m['durable_volume']); app = modal.App('rgec-real-native-matcher-census')
    with modal.enable_output(), app.run(detach=True):
        if m['sandbox'] is None:
            image = modal.Image.from_id(m['base_image_id'])
            for name in ('clang_matcher_census.cpp', 'native-census-build.py', 'matcher-census-config.json',
                'rgec_matcher_census_probe.py', 'modal_recipient_entry.py'):
                image = image.add_local_file(str(root / name), '/' + name, copy=True)
            image = image.run_commands('/usr/bin/python3 -I /native-census-build.py')
            sandbox = modal.Sandbox.create('/usr/bin/python3', '-I', '/rgec_matcher_census_probe.py',
                app=app, image=image, cpu=2, memory=8192, timeout=1200, block_network=True, volumes={'/retained': volume})
            m['sandbox'] = dict(id=sandbox.object_id, image_id=image.object_id); persist()
            print('Authentic native matcher census', sandbox.object_id, flush=True)
        else: sandbox = modal.Sandbox.from_id(m['sandbox']['id'])
        sandbox.wait(); m['sandbox']['cleanup_returncode'] = sandbox.returncode; persist()
        data = b''.join(volume.read_file(root.name + '/result.json')); (root / 'durable-result.json').write_bytes(data)
        result = json.loads(data); m['sandbox']['returncode'] = result['returncode']; persist()
        for name in ('raw.tar.gz', 'stdout', 'stderr'):
            data = b''.join(volume.read_file(root.name + '/' + name)); assert sha(data) == result[name + '_sha256']
            (root / name).write_bytes(data)
        m['sandbox']['raw_archive_sha256'] = result['raw.tar.gz_sha256']; persist()
        (root / 'raw').mkdir(exist_ok=True)
        with tarfile.open(root / 'raw.tar.gz') as archive:
            members = archive.getmembers(); assert len({v.name for v in members}) == len(members)
            for member in members:
                assert member.isfile() and member.name == 'raw/' + Path(member.name).name
                (root / member.name).write_bytes(archive.extractfile(member).read())
        print('Collected matcher census', result['returncode'], sandbox.returncode, flush=True)
        assert result['returncode'] == sandbox.returncode == 0


if __name__ == '__main__': main(Path(sys.argv[1]))
