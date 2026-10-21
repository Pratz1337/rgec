"""Build and run the scalar native-scope candidate on Modal only."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import modal


BINDINGS = r'''
import hashlib,json,re,struct
path='/rgec-knownbits-scope'; body=open(path,'rb').read(); original=body
assert body[:7]==b'\x7fELF\x02\x01\x01'
h=struct.unpack_from('<HHIQQQIHHHHHH',body,16)
assert h[0:2]==(2,62) and h[8]==56
def offset(pc,size):
 positions=[]
 for i in range(h[9]):
  kind,flags,off,address,_,filesize,_,_=struct.unpack_from('<II6Q',body,h[4]+i*56)
  if kind==1 and address<=pc and pc+size<=address+filesize:
   assert flags & 1 and not flags & 2
   positions.append(off+pc-address)
 result,=positions; return result
symbols={}
for line in subprocess.check_output(['/usr/bin/nm','-n','-S','--defined-only',path]).decode().splitlines():
 f=line.split()
 if len(f)==4: symbols[f[3]]=(int(f[0],16),int(f[1],16))
target='_ZNK4llvm12SelectionDAG16computeKnownBitsENS_7SDValueERNS_9KnownBitsERKNS_5APIntEj'
entry='_ZNK4llvm12SelectionDAG16computeKnownBitsENS_7SDValueERNS_9KnownBitsEj'
start,size=symbols[entry]; old=symbols[target][0]; new=symbols['__wrap_'+target][0]
disassembly=subprocess.check_output(['/usr/bin/objdump','-d','--start-address=%d'%start,'--stop-address=%d'%(start+size),path]).decode()
changes=[]
for line in disassembly.splitlines():
 match=re.match(r'^\s*([0-9a-f]+):.*\bcallq\s+([0-9a-f]+)\s',line)
 if not match or int(match.group(2),16)!=old: continue
 pc=int(match.group(1),16); pos=offset(pc,5); before=body[pos:pos+5]
 assert before[0]==0xe8 and pc+5+struct.unpack('<i',before[1:])[0]==old
 after=b'\xe8'+struct.pack('<i',new-pc-5)
 body=body[:pos]+after+body[pos+5:]
 changes.append(dict(pc=pc,file_offset=pos,old_target=old,new_target=new,original_hex=before.hex(),patched_hex=after.hex()))
assert len(changes)==1 and len(body)==len(original) and sum(a!=b for a,b in zip(body,original))<=4
regions=[]
for name in (target,entry,'__wrap_'+target):
 address,size=symbols[name]; pos=offset(address,size); data=body[pos:pos+size]
 regions.append(dict(symbol=name,address=address,size=size,file_offset=pos,sha256=hashlib.sha256(data).hexdigest()))
with open(path,'wb') as f: f.write(body)
with open('/knownbits-scope-binding.json','w') as f:
 json.dump(dict(unpatched_sha256=hashlib.sha256(original).hexdigest(),patched_sha256=hashlib.sha256(body).hexdigest(),
  changes=changes,regions=regions,entry_scope='Three-argument native KnownBits entry delegates to the experimental wrapper. Original demanded-element recursion remains native; separate-object --wrap bindings can also reach the wrapper.',
  semantic_certificate=False),f,indent=2)
'''


def sha(data): return hashlib.sha256(data).hexdigest()


def main(root):
    prior_root = Path('runs/rgec-modal-native-region-capsule-2026-10-10')
    prior = json.loads((prior_root/'evidence.json').read_bytes())
    v27 = Path('runs/rgec-modal-native-stream-admission-2026-10-09-v27')
    paths = [Path('modal_rgec_knownbits_scope.py'), Path('scripts/rgec_knownbits_scope_probe.py'),
        Path('scripts/rgec_knownbits_driver.py'), Path('src/unauthorized_channels/clang_knownbits_scope.cpp'),
        Path('src/unauthorized_channels/modal_recipient_entry.py')]
    manifest = root/'evidence.json'
    if not root.exists():
        root.mkdir(parents=True)
        for path in paths: (root/path.name).write_bytes(path.read_bytes())
        original = (v27/'native-build.py').read_text()
        needle = "command+=['/rgec-backend.cpp','-o','/rgec-backend','-Wl,--wrap='+symbol]"
        assert original.count(needle)==1
        build = original.replace(needle, "command+=['/rgec-backend.cpp','/knownbits-scope.o','-o','/rgec-knownbits-scope','-Wl,--wrap='+symbol]")
        target = '_ZNK4llvm12SelectionDAG16computeKnownBitsENS_7SDValueERNS_9KnownBitsERKNS_5APIntEj'
        build = build.replace("command+=['-Wl,--start-group']", "command+=['-Wl,--wrap="+target+"']\ncommand+=['-Wl,--start-group']")
        build = "import subprocess\nsubprocess.check_call(['/usr/local/bin/clang++','-O2','-std=c++14','-fno-rtti','-I/usr/local/include','-c','/clang_knownbits_scope.cpp','-o','/knownbits-scope.o'])\n"+build+'\n'+BINDINGS
        (root/'native-scope-build.py').write_text(build,encoding='utf-8')
        config = dict(prefix=root.name, blocks=3,
            native_sha256=json.loads((prior_root/'region-capsule-config.json').read_bytes())['native_sha256'],
            scope_source_sha256=sha((root/'clang_knownbits_scope.cpp').read_bytes()),
            flags=['-O1','-fno-omit-frame-pointer','-gline-tables-only','-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION',
                '-fsanitize=address','-fsanitize-address-use-after-scope','-fsanitize=fuzzer-no-link'])
        (root/'knownbits-scope-config.json').write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
        m = dict(platform='Modal',gpu=None,cpu=2,memory_mib=8192,base_image_id=prior['sandbox']['image_id'],
            durable_volume=prior['durable_volume'],source_sha256={p.as_posix():sha((root/p.name).read_bytes()) for p in paths},
            original_build_sha256=sha((v27/'native-build.py').read_bytes()),
            build_sha256=sha((root/'native-scope-build.py').read_bytes()),
            config_sha256=sha((root/'knownbits-scope-config.json').read_bytes()),sandbox=None,
            runtime_network_blocked=True,complete_closure_certified=False,adaptive_noninterference_proved=False,
            substantial_novelty_established=False,experimental_scope_policy=True,production_shared_policy_enabled=False)
        manifest.write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8')
    m=json.loads(manifest.read_bytes())
    for path,expected in m['source_sha256'].items(): assert sha((root/Path(path).name).read_bytes())==expected
    assert sha((root/'native-scope-build.py').read_bytes())==m['build_sha256']
    assert sha((root/'knownbits-scope-config.json').read_bytes())==m['config_sha256']
    def persist(): manifest.write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8')
    volume=modal.Volume.from_name(m['durable_volume']); app=modal.App('rgec-real-knownbits-scope')
    with modal.enable_output(),app.run(detach=True):
        if m['sandbox'] is None:
            image=modal.Image.from_id(m['base_image_id'])
            for name in ('clang_knownbits_scope.cpp','native-scope-build.py','knownbits-scope-config.json',
                'rgec_knownbits_scope_probe.py','rgec_knownbits_driver.py','modal_recipient_entry.py'):
                image=image.add_local_file(str(root/name),'/'+name,copy=True)
            image=image.run_commands('/usr/bin/python3 -I /native-scope-build.py',
                'cp /rgec_knownbits_driver.py /rgec-knownbits-driver && chmod 555 /rgec-knownbits-driver')
            sandbox=modal.Sandbox.create('/usr/bin/python3','-I','/rgec_knownbits_scope_probe.py',app=app,image=image,
                cpu=2,memory=8192,timeout=2400,block_network=True,volumes={'/retained':volume})
            m['sandbox']=dict(id=sandbox.object_id,image_id=image.object_id);persist()
            print('Real native scope construction',sandbox.object_id,flush=True)
        else: sandbox=modal.Sandbox.from_id(m['sandbox']['id'])
        sandbox.wait();m['sandbox']['cleanup_returncode']=sandbox.returncode;persist()
        data=b''.join(volume.read_file(root.name+'/result.json'));(root/'durable-result.json').write_bytes(data)
        result=json.loads(data);m['sandbox']['returncode']=result['returncode'];persist()
        for name in ('raw.tar.gz','stdout','stderr'):
            data=b''.join(volume.read_file(root.name+'/'+name));assert sha(data)==result[name+'_sha256']
            (root/name).write_bytes(data)
        m['sandbox']['raw_archive_sha256']=result['raw.tar.gz_sha256'];persist()
        with tarfile.open(root/'raw.tar.gz') as archive:
            members=archive.getmembers();assert len({p.name for p in members})==len(members)
            for member in members:
                path=Path(member.name);assert member.isfile() and path.parts[0]=='raw' and '..' not in path.parts
                output=root/path;output.parent.mkdir(parents=True,exist_ok=True)
                output.write_bytes(archive.extractfile(member).read())
        print('Collected real scope evidence',result['returncode'],sandbox.returncode,flush=True)
        assert result['returncode']==sandbox.returncode==0


if __name__=='__main__':main(Path(sys.argv[1]))
