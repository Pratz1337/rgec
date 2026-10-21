"""Construct conditional native memory contracts from retained real entries on Modal."""
import hashlib
import json
from pathlib import Path
import sys

import modal


WORKER = r'''
import hashlib,json,pathlib,shutil,subprocess,sys,tarfile,traceback
c=json.load(open('/config.json'));root=pathlib.Path('/native-contract');root.mkdir()
target=pathlib.Path('/retained')/c['output_prefix'];target.mkdir()
r={'returncode':1,'native_compiler_actions':0,'universal_native_certificate':False}
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
try:
 archive=pathlib.Path('/retained')/c['input_prefix']/'raw.tar.gz'
 witness=pathlib.Path('/retained')/c['input_prefix']/'native-model/native-transition-check.json'
 assert sha(archive)==c['archive_sha256'] and sha(witness)==c['witness_sha256']
 assert sha('/checker.py')==c['checker_sha256']
 with tarfile.open(archive) as a:
  members=a.getmembers();assert len({m.name for m in members})==len(members)
  for m in members:
   parts=pathlib.Path(m.name).parts;assert m.isfile() and parts[0]=='raw' and '..' not in parts
   if m.name!='raw/native-proof.elf' and not any(m.name.endswith(s) for s in ('.entry','.entry.maps','.entry.memory','.entry.after')):continue
   output=root/m.name;output.parent.mkdir(parents=True,exist_ok=True)
   with output.open('wb') as f:shutil.copyfileobj(a.extractfile(m),f)
 assert sha(root/'raw/native-proof.elf')==c['proof_elf_sha256']
 with (target/'stdout').open('wb') as out,(target/'stderr').open('wb') as err:
  r['returncode']=subprocess.call([sys.executable,'-I','/checker.py',str(root/'raw/native-proof.elf'),str(root/'raw'),str(witness),str(target/'native-contract.json')],stdout=out,stderr=err)
 if (target/'native-contract.json').exists():r['contract_sha256']=sha(target/'native-contract.json')
except BaseException:
 r['returncode']=1
 with (target/'stderr').open('a') as f:traceback.print_exc(file=f)
(target/'result.json').write_text(json.dumps(r,indent=2)+'\n')
sys.exit(r['returncode'])
'''


def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main(root, prior=Path('runs/rgec-modal-native-transition-2026-10-11-v4')):
    manifest=root/'evidence.json'
    if not root.exists():
        root.mkdir(parents=True)
        for source in (Path(__file__),Path('scripts/derive_rgec_native_contract.py')):
            (root/source.name).write_bytes(source.read_bytes())
        (root/'worker.py').write_bytes(WORKER.encode('utf-8'))
        previous=json.loads((prior/'evidence.json').read_bytes())
        model=json.loads((prior/'native-model/native-transition-check.json').read_bytes())
        config=dict(input_prefix=prior.name,output_prefix=prior.name+'/'+root.name,
            archive_sha256=sha(prior/'raw.tar.gz'),witness_sha256=sha(prior/'native-model/native-transition-check.json'),
            proof_elf_sha256=model['binary_sha256'],checker_sha256=sha(root/'derive_rgec_native_contract.py'))
        (root/'config.json').write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
        m=dict(platform='Modal',gpu=None,base_image_id='im-AXRKdbfotKAXxTC04bt2Dn',durable_volume=previous['durable_volume'],
            frozen_sha256={name:sha(root/name) for name in ('modal_rgec_native_contract.py','derive_rgec_native_contract.py','worker.py','config.json')},
            native_compiler_actions=0,worker=None,universal_native_certificate=False,runtime_admission_implemented=False,
            substantial_novelty_established=False)
        manifest.write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8')
    m=json.loads(manifest.read_bytes());config=json.loads((root/'config.json').read_bytes())
    for name,digest in m['frozen_sha256'].items():assert sha(root/name)==digest
    assert sha(prior/'raw.tar.gz')==config['archive_sha256']
    assert sha(prior/'native-model/native-transition-check.json')==config['witness_sha256']
    def persist():manifest.write_text(json.dumps(m,indent=2)+'\n',encoding='utf-8')
    volume=modal.Volume.from_name(m['durable_volume']);app=modal.App('rgec-native-contract-construction')
    with modal.enable_output(),app.run(detach=True):
        if m['worker'] is None:
            image=modal.Image.from_id(m['base_image_id'])
            for name,remote in (('derive_rgec_native_contract.py','/checker.py'),('worker.py','/worker.py'),('config.json','/config.json')):
                image=image.add_local_file(str(root/name),remote,copy=True)
            worker=modal.Sandbox.create('python3','-I','/worker.py',app=app,image=image,cpu=2,memory=16384,
                timeout=2400,block_network=True,volumes={'/retained':volume})
            m['worker']=dict(id=worker.object_id,image_id=image.object_id);persist()
            print('Conditional native contract construction',worker.object_id,flush=True)
        else:worker=modal.Sandbox.from_id(m['worker']['id'])
        worker.wait();m['worker']['cleanup_returncode']=worker.returncode;persist()
        for name in ('result.json','stdout','stderr'):
            (root/name).write_bytes(b''.join(volume.read_file(config['output_prefix']+'/'+name)))
        result=json.loads((root/'result.json').read_bytes());m['worker']['returncode']=result['returncode'];persist()
        if 'contract_sha256' in result:
            name='native-contract.json';(root/name).write_bytes(b''.join(volume.read_file(config['output_prefix']+'/'+name)))
            assert sha(root/name)==result['contract_sha256']
            m['worker']['contract_sha256']=result['contract_sha256'];persist()
        assert result['returncode']==worker.returncode==0,result
        print('Native contract evidence collected',flush=True)


if __name__=='__main__':main(Path(sys.argv[1]),Path(sys.argv[2]) if len(sys.argv)>2 else Path('runs/rgec-modal-native-transition-2026-10-11-v4'))
