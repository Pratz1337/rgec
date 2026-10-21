"""Run byte audits of durable native samples, census or scalar scope on Modal."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import modal


WORKER = r'''
import hashlib,json,os,pathlib,shutil,subprocess,sys,tarfile,traceback
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
c=json.load(open('/config.json')); root=pathlib.Path('/audit-work'); root.mkdir()
target=pathlib.Path('/retained')/c['prefix']/c['audit_name']; target.mkdir()
(target/'stdout').touch(); (target/'stderr').touch()
r={'returncode':1,'auditor_compiler_actions':0}
try:
 assert sha('/auditor.py')==c['auditor_sha256'] and sha('/inputs.tar.gz')==c['inputs_sha256']
 with tarfile.open('/inputs.tar.gz') as a:
  members=a.getmembers(); assert len({m.name for m in members})==len(members)
  for m in members:
   assert m.isfile() and m.name=='raw/'+os.path.basename(m.name)
   with (root/os.path.basename(m.name)).open('wb') as f: shutil.copyfileobj(a.extractfile(m),f)
 assert sha(root/'evidence.json')==c['manifest_sha256']
 for name in ('raw.tar.gz','stdout','stderr'): os.symlink('/retained/'+c['prefix']+'/'+name,str(root/name))
 (root/'raw').mkdir()
 with tarfile.open(str(root/'raw.tar.gz')) as a:
  members=a.getmembers(); assert len({m.name for m in members})==len(members)
  for m in members:
   parts=pathlib.Path(m.name).parts
   assert m.isfile() and parts[0]=='raw' and '..' not in parts
   (root/m.name).parent.mkdir(parents=True,exist_ok=True)
   with (root/m.name).open('wb') as f: shutil.copyfileobj(a.extractfile(m),f)
 with (target/'stdout').open('wb') as out,(target/'stderr').open('wb') as err:
  r['returncode']=subprocess.call([sys.executable,'-I','/auditor.py',str(root)],stdout=out,stderr=err)
 if r['returncode']==0:
  shutil.copyfile(str(root/c['output_name']),str(target/c['output_name']))
  r['audit_sha256']=sha(target/c['output_name'])
  if (root/'independent-native-bindings.stdout').exists():
   shutil.copyfile(str(root/'independent-native-bindings.stdout'),str(target/'independent-native-bindings.stdout'))
except BaseException:
 r['returncode']=1
 with (target/'stderr').open('a') as f: traceback.print_exc(file=f)
(target/'result.json').write_text(json.dumps(r,indent=2)+'\n')
sys.exit(r['returncode'])
'''


def sha(data): return hashlib.sha256(data).hexdigest()


def main(root, audit_name, census=False, knownbits=False, transition=False, contract=False, cost=False):
    raw = (root / 'evidence.json').read_bytes(); m = json.loads(raw)
    execution = m['capture'] if transition else m['sandbox']
    assert execution['returncode'] == execution['cleanup_returncode'] == 0
    folder = root / audit_name; folder.mkdir(exist_ok=False)
    auditor = Path('scripts/audit_rgec_native_cost.py' if cost else 'scripts/audit_rgec_native_transition.py' if transition else 'scripts/audit_rgec_knownbits_scope.py' if knownbits else 'scripts/audit_rgec_matcher_census.py' if census else 'scripts/audit_rgec_native_samples.py')
    output_name = 'independent-native-cost-audit.json' if cost else 'independent-native-transition-audit.json' if transition else 'independent-knownbits-audit.json' if knownbits else 'independent-matcher-audit.json' if census else 'independent-sample-audit.json'
    if contract: output_name = 'independent-native-contract-audit.json'
    for path in (Path(__file__), auditor): (folder / path.name).write_bytes(path.read_bytes())
    worker = folder / 'cloud-worker.py'; worker.write_text(WORKER, encoding='utf-8')
    names = {Path(p).name for p in m['source_sha256']}
    names.update(('evidence.json', 'knownbits-scope-config.json' if knownbits or transition or cost else 'matcher-census-config.json' if census else 'segment-profile-config.json', 'result.json' if transition or cost else 'durable-result.json'))
    if census: names.add('native-census-build.py')
    if knownbits: names.add('native-scope-build.py')
    if transition: names.update(m['generated_sha256'])
    if cost: names.update(m['generated_sha256'])
    with tarfile.open(folder / 'inputs.tar.gz', 'w:gz') as archive:
        for name in sorted(names): archive.add(root / name, arcname='raw/' + name)
        if transition: archive.add(root / 'native-model/native-transition-check.json', arcname='raw/native-transition-check.json')
        if contract:
            contract_root = root / 'address-contract-v1'
            for name in ('evidence.json','result.json','native-contract.json','modal_rgec_native_contract.py','derive_rgec_native_contract.py','worker.py','config.json'):
                archive.add(contract_root / name, arcname='raw/' + ('native-contract.json' if name == 'native-contract.json' else 'contract-' + name))
    config = dict(prefix=root.name, audit_name=audit_name, output_name=output_name, manifest_sha256=sha(raw),
        auditor_sha256=sha(auditor.read_bytes()), inputs_sha256=sha((folder / 'inputs.tar.gz').read_bytes()))
    config_path = folder / 'config.json'; config_path.write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8')
    evidence = dict(config, worker_sha256=sha(worker.read_bytes()), controller_sha256=sha(Path(__file__).read_bytes()), auditor_compiler_actions=0)
    def persist(): (folder / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    persist()
    native_tools = census or knownbits or transition or cost
    image = modal.Image.from_id(execution['image_id']) if native_tools else modal.Image.debian_slim(python_version='3.11')
    for local, remote in ((folder / auditor.name, '/auditor.py'), (worker, '/cloud-worker.py'),
        (folder / 'inputs.tar.gz', '/inputs.tar.gz'), (config_path, '/config.json')):
        image = image.add_local_file(str(local), remote, copy=True)
    volume = modal.Volume.from_name(m['durable_volume']); app = modal.App('rgec-independent-native-sample-audit')
    with modal.enable_output(), app.run(detach=True):
        sandbox = modal.Sandbox.create('/usr/bin/python3' if native_tools else 'python3', '-I', '/cloud-worker.py', app=app, image=image,
            cpu=2, memory=4096, timeout=900, block_network=True, volumes={'/retained': volume})
        evidence.update(sandbox_id=sandbox.object_id, image_id=image.object_id); persist()
        print('Data-only sample auditor', sandbox.object_id, flush=True)
        sandbox.wait(); evidence['cleanup_returncode'] = sandbox.returncode; persist()
        remote = root.name + '/' + audit_name + '/'
        for name in ('result.json', 'stdout', 'stderr'):
            (folder / name).write_bytes(b''.join(volume.read_file(remote + name)))
        result = json.loads((folder / 'result.json').read_bytes()); evidence['returncode'] = result['returncode']; persist()
        assert result['returncode'] == evidence['cleanup_returncode'] == 0, result
        output = b''.join(volume.read_file(remote + output_name))
        assert sha(output) == result['audit_sha256']
        (root / output_name).write_bytes(output)
        evidence['audit_sha256'] = sha(output); persist()
        audit = json.loads(output)
        fields = ('native_compiler_actions', 'complete_zlib_workflows', 'all_sample_records', 'outer_sample_records', 'nested_wrapped_records') if cost else ('native_compiler_actions', 'complete_zlib_workflows', 'native_entry_snapshots', 'model_transition_witnesses', 'native_model_rejections') if transition else ('native_compiler_actions', 'complete_zlib_workflows', 'scalar_packet_answers', 'build_medians_seconds') if knownbits else ('native_compiler_actions', 'literal_status_stream_object_pairs', 'invocation_totals', 'mask_path_totals') if census else ('native_compiler_actions', 'samples', 'sample_totals', 'status_object_stdout_pairs')
        if native_tools and not cost:
            bindings = b''.join(volume.read_file(remote + 'independent-native-bindings.stdout'))
            assert sha(bindings) == audit['independent_disassembly_sha256']
            (root / 'independent-native-bindings.stdout').write_bytes(bindings)
        print(json.dumps({k: audit[k] for k in fields}))


if __name__ == '__main__': main(Path(sys.argv[1]), sys.argv[2], len(sys.argv) > 3 and sys.argv[3] == 'census', len(sys.argv) > 3 and sys.argv[3] == 'knownbits', len(sys.argv) > 3 and sys.argv[3] in ('transition','contract'), len(sys.argv) > 3 and sys.argv[3] == 'contract', len(sys.argv) > 3 and sys.argv[3] == 'cost')
