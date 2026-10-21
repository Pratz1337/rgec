"""Audit existing durable native stream evidence on a data-only Modal worker."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import modal


WORKER = r'''
import hashlib,json,os,pathlib,shutil,subprocess,sys,tarfile,traceback
digest=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
c=json.load(open('/audit-config.json')); root=pathlib.Path('/audit-work'); root.mkdir()
target=pathlib.Path('/retained')/c['prefix']/c['audit_name']; target.mkdir()
r={'returncode':1,'native_compiler_actions':0,'auditor_sha256':digest('/audit_rgec_native_streams.py')}
try:
 assert r['auditor_sha256']==c['auditor_sha256']
 assert digest('/audit-inputs.tar.gz')==c['inputs_sha256']
 with tarfile.open('/audit-inputs.tar.gz') as a:
  members=a.getmembers(); assert len({m.name for m in members})==len(members)
  for m in members:
   assert m.isfile() and m.name=='raw/'+os.path.basename(m.name)
   with (root/os.path.basename(m.name)).open('wb') as f: shutil.copyfileobj(a.extractfile(m),f)
 assert digest(root/'evidence.json')==c['manifest_sha256']
 for name in ('raw.tar.gz','stdout','stderr'):
  os.symlink('/retained/'+c['prefix']+'/'+name,root/name)
 (root/'raw').mkdir()
 with tarfile.open(root/'raw.tar.gz') as a:
  members=a.getmembers(); assert len({m.name for m in members})==len(members)
  for m in members:
   assert m.isfile() and m.name=='raw/'+os.path.basename(m.name)
   with (root/m.name).open('wb') as f: shutil.copyfileobj(a.extractfile(m),f)
 with (target/'stdout').open('wb') as out,(target/'stderr').open('wb') as err:
  r['returncode']=subprocess.call([sys.executable,'-I','/audit_rgec_native_streams.py',str(root)],stdout=out,stderr=err)
 if r['returncode']==0:
  shutil.copyfile(root/'independent-stream-audit.json',target/'independent-stream-audit.json')
  r['audit_sha256']=digest(target/'independent-stream-audit.json')
except BaseException:
 with (target/'stderr').open('a') as f: traceback.print_exc(file=f)
(target/'result.json').write_text(json.dumps(r,indent=2)+'\n')
sys.exit(r['returncode'])
'''


def sha(data): return hashlib.sha256(data).hexdigest()


def main(root, audit_name):
    raw=(root/'evidence.json').read_bytes(); m=json.loads(raw)
    assert m['sandbox']['returncode']==m['sandbox']['cleanup_returncode']==0
    folder=root/audit_name; folder.mkdir(exist_ok=False)
    auditor=Path('scripts/audit_rgec_native_streams.py')
    for path in (Path(__file__),auditor): (folder/path.name).write_bytes(path.read_bytes())
    worker=folder/'cloud-worker.py'; worker.write_text(WORKER,encoding='utf-8')
    names={p.replace('\\','/').split('/')[-1] for p in m['source_sha256']}
    names.update(('evidence.json','baseline-evidence.json','stream-config.json','durable-result.json'))
    if m.get('build_native'): names.update(('native-build.py','build-fingerprint.stdout','build-fingerprint.stderr'))
    with tarfile.open(folder/'inputs.tar.gz','w:gz') as archive:
        for name in sorted(names): archive.add(root/name,arcname='raw/'+name)
        for source in ('adler32.c','deflate.c','FuzzerUtil.cpp'):
            path=Path(m['baseline_root'])/'reports'/(source+'.original')
            archive.add(path,arcname='raw/baseline-'+source+'.original')
    config={'prefix':root.name,'audit_name':audit_name,'manifest_sha256':sha(raw),
        'auditor_sha256':sha(auditor.read_bytes()),'inputs_sha256':sha((folder/'inputs.tar.gz').read_bytes())}
    config_path=folder/'config.json'; config_path.write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
    evidence=dict(config,controller_sha256=sha(Path(__file__).read_bytes()),worker_sha256=sha(worker.read_bytes()),native_compiler_actions=0)
    def persist(): (folder/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    persist()
    image=modal.Image.debian_slim(python_version='3.11')
    for local,remote in ((auditor,'/audit_rgec_native_streams.py'),(worker,'/cloud-worker.py'),
        (folder/'inputs.tar.gz','/audit-inputs.tar.gz'),(config_path,'/audit-config.json')):
        image=image.add_local_file(str(local),remote,copy=True)
    volume=modal.Volume.from_name(m['durable_volume']); app=modal.App('rgec-independent-native-stream-byte-audit')
    with modal.enable_output(),app.run(detach=True):
        sandbox=modal.Sandbox.create('python3','-I','/cloud-worker.py',app=app,image=image,
            cpu=2,memory=4096,timeout=1800,block_network=True,volumes={'/retained':volume})
        evidence.update(sandbox_id=sandbox.object_id,image_id=image.object_id); persist()
        print('Data-only stream auditor',sandbox.object_id,flush=True)
        sandbox.wait(); evidence['cleanup_returncode']=sandbox.returncode; persist()
        remote=root.name+'/'+audit_name+'/'
        for name in ('result.json','stdout','stderr'):
            (folder/name).write_bytes(b''.join(volume.read_file(remote+name)))
        result=json.loads((folder/'result.json').read_bytes()); evidence['returncode']=result['returncode']; persist()
        assert result['auditor_sha256']==config['auditor_sha256']
        assert result['returncode']==evidence['cleanup_returncode']==0,result
        output=b''.join(volume.read_file(remote+'independent-stream-audit.json'))
        assert sha(output)==result['audit_sha256']
        (root/'independent-stream-audit.json').write_bytes(output)
        evidence['audit_sha256']=sha(output); persist()
        audit=json.loads(output)
        print(json.dumps({k:audit[k] for k in ('comparison_totals','trace_control_totals','native_repeat_totals')}))


if __name__=='__main__': main(Path(sys.argv[1]),sys.argv[2])
