"""Real complete builds with private cloud-local authenticated lookup and plans."""
import json
from pathlib import Path
import random
import struct
import sys
from datetime import datetime, timezone

import modal
from modal_rgec_native import execute, sha
from modal_rgec_residual import collect


def main(root):
    prior_root=Path('runs/rgec-modal-full-zlib-authenticated-2026-10-05-v22')
    prior=json.loads((prior_root/'evidence.json').read_text())
    audit=json.loads((prior_root/'independent-full-zlib-store-audit.json').read_text())
    assert audit['complete_functional_suite'] and sha((prior_root/'evidence.json').read_bytes())==audit['manifest_sha256']
    assert all(row['cleanup_returncode']==137 for row in prior['sandboxes'])
    root.mkdir(parents=True,exist_ok=False)
    paths=[Path(__file__),Path('modal_rgec_native.py'),Path('modal_rgec_residual.py'),
        Path('src/unauthorized_channels/backend_recipe_store.py'),
        Path('src/unauthorized_channels/modal_recipient_entry.py')]+[Path('scripts')/name for name in
        ('rgec_full_zlib_probe.py','rgec_zlib_compiler_broker.py','rgec_zlib_compiler_proxy.py',
         'rgec_backend_probe.py','rgec_native_effect_probe.py','rgec_native_event_probe.py')]
    for path in paths:(root/path.name).write_bytes(path.read_bytes())
    (root/'zlib-native-commands.json').write_bytes((prior_root/'zlib-native-commands.json').read_bytes())
    context={'protocol':'RGECB3','image_id':prior['sandboxes'][0]['image_id'],
        'backend_sha256':prior['tool_sha256']['/rgec-backend'],
        'compiler_sha256':prior['tool_sha256']['/usr/local/bin/clang'],
        'native_commands_sha256':sha((root/'zlib-native-commands.json').read_bytes())}
    cold=json.loads((prior_root/'policy-cold/evidence.json').read_text())
    preload={'context':context,'receipts':[],'driver_plans':[],'packets':{}}
    for action in cold['compiler_actions']:
        if not action['is_compile']:continue
        profile=action['arguments'][action['arguments'].index('-o')+1]
        entry=next(row for row in prior['store_audit'] if row['profile']==profile and row['route']=='separate-producer-miss')
        packet=(prior_root/'policy-cold'/(action['label']+'.reply')).read_bytes()
        assert sha(packet)==action['reply_sha256'] and packet[:6]==b'RGECB3'
        preload['packets'][profile]=packet.hex()
        preload['receipts'].append({'version':1,'context':context,'profile':profile,'binding':'computation',
            'key_sha256':entry['key_sha256'],'packet_sha256':sha(packet),'origin':entry['origin'],
            'complete_closure_certified':False})
        bound=(prior_root/'policy-cold'/(action['label']+'.query')).read_bytes()
        offset=8;count=struct.unpack_from('<Q',bound)[0];arguments=[]
        for _ in range(count):
            size=struct.unpack_from('<Q',bound,offset)[0];offset+=8
            arguments.append(bound[offset:offset+size].decode());offset+=size
        resource=arguments[arguments.index('-resource-dir')+1]
        preload['driver_plans'].append({'arguments':action['arguments'],
            'wrapped_argv':['/rgec-driver/clang-7','-no-canonical-prefixes','-ccc-install-dir',
                '/usr/local/bin','-resource-dir',resource]+action['arguments'],
            'native_cc1_arguments':arguments,'validated_native_query_sha256':action['query_sha256']})
    assert len(preload['receipts'])==len(preload['driver_plans'])==19
    (root/'preload.json').write_text(json.dumps(preload,separators=(',',':')),encoding='utf-8')
    rng=random.Random(6317);order=[]
    for block in range(3):
        modes=['native','local-warm'];rng.shuffle(modes)
        order.extend({'block':block,'mode':mode,'phase':'block-'+str(block)+'-'+mode} for mode in modes)
    evidence={'date':datetime.now(timezone.utc).date().isoformat(),'platform':'Modal','gpu':None,
        'cpu_per_sandbox':2,'memory_mib':4096,'runtime_network_blocked':True,'planned_order':order,
        'source_sha256':{str(path):sha(path.read_bytes()) for path in paths},
        'tool_sha256':prior['tool_sha256'],'prior_authenticated_manifest_sha256':audit['manifest_sha256'],
        'preload_sha256':sha((root/'preload.json').read_bytes()),'preload_bytes':(root/'preload.json').stat().st_size,
        'native_commands_sha256':sha((root/'zlib-native-commands.json').read_bytes()),
        'sandboxes':[],'production_shared_policy_enabled':False,'adaptive_noninterference_proved':False,
        'scope':'Three seeded order blocks, independent native/prepopulated Modal workers, complete actual zlib workflows. No local-miss producer, scheduling or held-out task experiment.'}
    image=modal.Image.from_id('im-SK4se5LNRr17uHdZsLB4nT')
    for path in paths[4:]:image=image.add_local_file(str(root/path.name),'/'+path.name,copy=True)
    image=image.add_local_file(str(root/'backend_recipe_store.py'),'/rgec-private/cache/backend_recipe_store.py',copy=True)
    image=image.add_local_file(str(root/'preload.json'),'/rgec-private/cache/preload.json',copy=True)
    image=image.add_local_file(str(root/'zlib-native-commands.json'),'/zlib-native-commands.json',copy=True)
    image=image.run_commands("chmod 700 /rgec-private /rgec-private/cache && "
        "cp /rgec_zlib_compiler_proxy.py /rgec-zlib-compiler && chmod 555 /rgec-zlib-compiler && "
        "/usr/bin/python3 -I -c 'import json,os; p=json.load(open(\"/rgec-private/cache/preload.json\")); "
        "[open(\"/rgec-private/cache/\"+name+\".packet\",\"wb\").write(bytes.fromhex(data)) for name,data in p[\"packets\"].items()]'")
    def persist():(root/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    app=modal.App('rgec-cloud-local-complete-zlib')
    try:
        with modal.enable_output(),app.run():
            for item in order:
                sandbox=modal.Sandbox.create('/bin/sleep','infinity',app=app,image=image,cpu=2,memory=4096,
                    timeout=1800,block_network=True)
                row=dict(item,id=sandbox.object_id,image_id=image.object_id);evidence['sandboxes'].append(row);persist()
                print('Bound',item['phase'],sandbox.object_id,flush=True)
                try:
                    code,out,error=execute(sandbox,'/usr/bin/sha256sum',*prior['tool_sha256'].keys(),
                        '/rgec-private/cache/preload.json','/zlib-native-commands.json')
                    actual={line.split()[1]:line.split()[0] for line in out.decode().splitlines()}
                    assert code==0 and all(actual[name]==digest for name,digest in prior['tool_sha256'].items()),error
                    assert actual['/rgec-private/cache/preload.json']==evidence['preload_sha256']
                    assert actual['/zlib-native-commands.json']==evidence['native_commands_sha256']
                    row['tool_sha256']=prior['tool_sha256'];persist()
                    code,out,error=execute(sandbox,'/usr/bin/python3','-I','/rgec_full_zlib_probe.py',item['mode'],timeout=900)
                    row['returncode']=code
                    (root/(item['phase']+'.stdout')).write_bytes(out);(root/(item['phase']+'.stderr')).write_bytes(error)
                    row['raw_archive_sha256']=collect(sandbox,root,item['phase'],'/rgec-private/zlib');persist()
                    assert code==0,error[-4000:]
                    program="""import json,sys
sys.path.insert(0,'/')
from rgec_backend_probe import run
from modal_recipient_entry import ENV
paths=['/rgec-private/cache/preload.json','/rgec-private/cache/backend_recipe_store.py',
 '/rgec-private/zlib/evidence.json','/rgec-private/zlib/compile-00.control',
 '/rgec-private/zlib/raw.tar.gz','/proc/1/root/rgec-private/cache/preload.json',
 '/workspace/backend-continuation/project/zlib.h']
rows=[]
for path in paths:
 code,out,error=run(['/usr/bin/python3','-I','-c',
  'import sys;open(sys.argv[1],"rb").read();print("readable")',path],'/workspace/backend-continuation/project')
 rows.append({'path':path,'returncode':code,'stdout_hex':out.hex(),'stderr_hex':error.hex()})
assert all(row['returncode']!=0 and b'PermissionError' in bytes.fromhex(row['stderr_hex']) for row in rows[:-1]),rows
assert rows[-1]['returncode']==0,rows
print(json.dumps(rows))
"""
                    code,out,error=execute(sandbox,'/usr/bin/python3','-I','-c',program)
                    (root/(item['phase']+'.authority.stdout')).write_bytes(out)
                    (root/(item['phase']+'.authority.stderr')).write_bytes(error)
                    row['authority_returncode']=code;row['authority_stdout_sha256']=sha(out);persist()
                    assert code==0,error
                    phase=json.loads((root/item['phase']/'evidence.json').read_text())
                    assert phase['outputs']==cold['outputs'] and phase['roundtrips']==cold['roundtrips']
                    if item['mode']=='local-warm':
                        assert len(phase['trusted_local_store_audit'])==19
                        assert all(entry['route']=='authenticated-hit' for entry in phase['trusted_local_store_audit'])
                    print(item['phase'],'full native outputs and tests match; private-file access denied',flush=True)
                finally:
                    sandbox.terminate()
                    try:sandbox.wait()
                    except (modal.exception.SandboxTerminatedError,modal.exception.SandboxTimeoutError):pass
                    row['cleanup_returncode']=sandbox.returncode;persist()
    except Exception as error:evidence['error']=repr(error);persist();raise
    finally:persist()


if __name__=='__main__':main(Path(sys.argv[1]))
