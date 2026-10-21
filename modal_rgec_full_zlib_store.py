"""Actual complete zlib native/cold/shared builds on Modal, with host receipts."""
import json
import shlex
from datetime import datetime, timezone
from pathlib import Path
import sys

import modal
from modal_rgec_native import execute, read, sha, write
from modal_rgec_residual import collect
from unauthorized_channels.backend_recipe_store import BackendRecipeStore, key_files


def main(root):
    component = Path('runs/rgec-modal-backend-read-state-2026-10-05-v22')
    prior = json.loads((component/'evidence.json').read_text())
    tools = json.loads((component/'producer/evidence.json').read_text())['tool_sha256']
    assert all(s['returncode']==0 and s['cleanup_returncode']==137 for s in prior['sandboxes'])
    native = [Path('src/unauthorized_channels')/name for name in
        ('clang_backend_continuation.cpp','clang_residual_backend.h','clang_backend_read_state.h')]
    for path, remote in zip(native,('/rgec-backend.cpp','/clang_residual_backend.h','/clang_backend_read_state.h')):
        assert sha(path.read_bytes())==tools[remote]
    reference = Path('runs/rgec-modal-full-zlib-native-2026-10-05-v20-v2')
    reference_manifest = json.loads((reference/'evidence.json').read_text())
    assert reference_manifest['sandboxes'][0]['returncode']==0
    commands = [shlex.split(line)[1:] for line in (reference/'v20/build.stdout').read_text().splitlines()
                if line.startswith('/usr/local/bin/clang ')]
    assert len(commands)==23 and sum('-c' in args for args in commands)==19
    root.mkdir(parents=True,exist_ok=False)
    paths = [Path(__file__),Path('modal_rgec_native.py'),Path('modal_rgec_residual.py'),
        Path('src/unauthorized_channels/backend_recipe_store.py'),
        Path('src/unauthorized_channels/modal_recipient_entry.py')] + native + [Path('scripts')/name for name in
        ('rgec_full_zlib_probe.py','rgec_zlib_compiler_proxy.py','rgec_zlib_compiler_broker.py',
         'rgec_backend_probe.py','rgec_native_effect_probe.py','rgec_native_event_probe.py','rgec_residual_probe.py')]
    evidence = {'date':datetime.now(timezone.utc).date().isoformat(),'platform':'Modal','gpu':None,
        'cpu_per_sandbox':2,'memory_mib':4096,'runtime_network_blocked':True,
        'source_sha256':{str(path):sha(path.read_bytes()) for path in paths},'sandboxes':[],
        'native_commands':commands,'native_reference_manifest_sha256':sha((reference/'evidence.json').read_bytes()),
        'native_commands_source_sha256':sha((reference/'v20/build.stdout').read_bytes()),
        'tool_sha256':tools,'store_audit':[],'comparisons':[],
        'experimental_fixed_workflow':True,'concurrent_make_tested':False,
        'production_shared_policy_enabled':False,'complete_closure_certified':False,
        'adaptive_noninterference_proved':False}
    for path in paths: (root/path.name).write_bytes(path.read_bytes())
    (root/'native-reference-build.stdout').write_bytes((reference/'v20/build.stdout').read_bytes())
    (root/'native-reference-manifest.json').write_bytes((reference/'evidence.json').read_bytes())
    (root/'zlib-native-commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    image = modal.Image.from_id(prior['sandboxes'][0]['image_id'])
    for path in paths[4:5]+paths[8:]:
        image = image.add_local_file(str(root/path.name), '/'+path.name, copy=True)
    image = image.add_local_file(str(root/'zlib-native-commands.json'),'/zlib-native-commands.json',copy=True)
    image = image.run_commands('cp /rgec_zlib_compiler_proxy.py /rgec-zlib-compiler && chmod 555 /rgec-zlib-compiler')
    sandboxes = []
    app = modal.App('rgec-authenticated-complete-zlib')
    def persist(): (root/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
    def bind(role):
        sandbox = modal.Sandbox.create('/bin/sleep','infinity',app=app,image=image,cpu=2,memory=4096,
            timeout=7200,block_network=True)
        sandboxes.append(sandbox)
        row = {'id':sandbox.object_id,'role':role,'image_id':image.object_id}
        evidence['sandboxes'].append(row);persist()
        status,out,error=execute(sandbox,'/usr/bin/sha256sum',*tools.keys())
        assert status==0 and {line.split()[1]:line.split()[0] for line in out.decode().splitlines()}==tools,error
        row['tool_sha256']=tools;persist()
        print('Bound',role,sandbox.object_id,flush=True)
        return sandbox,row
    def terminate(sandbox,row):
        sandbox.terminate()
        try:sandbox.wait()
        except (modal.exception.SandboxTerminatedError,modal.exception.SandboxTimeoutError):pass
        row['cleanup_returncode']=sandbox.returncode;persist()
    def producer(profile,bound):
        sandbox,row=bind('separate-full-project-producer')
        folder=root/sandbox.object_id;folder.mkdir()
        write(sandbox,'/producer.key',bound)
        descriptor={'cwd':'/workspace/backend-continuation/project',
            'files':[(name,data.hex()) for name,data in key_files(bound)]}
        write(sandbox,'/producer-files.json',json.dumps(descriptor).encode())
        program="""import json,os,sys
sys.path.insert(0,'/')
from rgec_backend_probe import run,packet_info
from rgec_residual_probe import state_input
from rgec_native_effect_probe import sha
p=json.load(open('/producer-files.json'));bound=open('/producer.key','rb').read()
for path in ('/producer.key','/producer-files.json'):os.chmod(path,0o600)
os.makedirs(p['cwd']+'/test');os.chown(p['cwd'],65534,65534);os.chown(p['cwd']+'/test',65534,65534)
protected=set()
for name,contents in p['files']:
 if name.startswith('<'):continue
 path=os.path.realpath(os.path.join(p['cwd'],name))
 assert path.startswith((p['cwd']+'/', '/usr/')),path
 if path.startswith(p['cwd']+'/'):
  os.makedirs(os.path.dirname(path),exist_ok=True);open(path,'wb').write(bytes.fromhex(contents))
 if os.path.isfile(path):os.chmod(path,0);protected.add(path)
arguments=state_input(bound)['arguments']
fresh,out,error=run(['/rgec-backend','-cc1']+arguments,p['cwd'],'record')
open('/fresh.control','wb').write(out);open('/fresh.stderr','wb').write(error)
assert fresh==1 and not out,(fresh,out[:100],error[-1000:])
status,out,error=run(['/rgec-backend','--rgec-produce-parametric'],p['cwd'],None,bound)
open('/producer.packet','wb').write(out);open('/producer.stderr','wb').write(error)
info=packet_info(out);assert info['key_sha256']==sha(bound)
output=arguments[arguments.index('-o')+1]
if os.path.isfile(p['cwd']+'/'+output):
 open('/producer.object','wb').write(open(p['cwd']+'/'+output,'rb').read())
print(json.dumps({'returncode':status,'reusable':info['reusable'],
 'packet_sha256':sha(out),'captured_context_sha256':sha(bound),
 'computation_key_sha256':info['computation_key_sha256'],
 'protected_files':len(protected),'fresh_frontend_returncode':fresh,'fresh_frontend_packet':False}))
"""
        try:
            status,out,error=execute(sandbox,'/usr/bin/python3','-I','-c',program,timeout=240)
            row['returncode']=status
            (folder/'controller.stdout').write_bytes(out);(folder/'controller.stderr').write_bytes(error)
            persist();assert status==0,error[-4000:]
            origin=json.loads(out)
            for filename in ('producer.key','producer.packet','producer.stderr','fresh.control','fresh.stderr','producer.object'):
                (folder/filename).write_bytes(read(sandbox,'/'+filename))
            packet=(folder/'producer.packet').read_bytes();assert sha(packet)==origin['packet_sha256']
            origin.update(sandbox_id=sandbox.object_id,image_id=image.object_id,native_tools_verified=True)
            (folder/'origin.json').write_text(json.dumps(origin,indent=2)+'\n')
            return packet,origin
        finally:terminate(sandbox,row)
    try:
        with modal.enable_output(),app.run():
            store=None
            for role,mode in (('native','native'),('wrapped-cold','wrapped-cold'),('policy-cold','replay'),('policy-peer-warm','replay')):
                sandbox,row=bind(role)
                if store is None:
                    store=BackendRecipeStore({'protocol':'RGECB3','image_id':image.object_id,
                        'backend_sha256':tools['/rgec-backend'],'compiler_sha256':tools['/usr/local/bin/clang'],
                        'native_commands_sha256':sha((root/'zlib-native-commands.json').read_bytes())},producer)
                row['phase']=role;row['mode']=mode;persist()
                process=sandbox.exec('/usr/bin/python3','-I','/rgec_full_zlib_probe.py',mode,text=True,bufsize=1,timeout=4800)
                frames=[]
                try:
                    for line in process.stdout:
                        frames.append(line);frame=json.loads(line)
                        if frame['phase']=='query':
                            query=read(sandbox,'/rgec-private/zlib/'+frame['label']+'.query')
                            assert sha(query)==frame['query_sha256']
                            packet=store.resolve(frame['profile'],query)
                            evidence['store_audit']=store.audit;persist()
                            write(sandbox,'/rgec-private/zlib/'+frame['label']+'.reply',packet)
                            process.stdin.write(json.dumps({'op':'continue'})+'\n');process.stdin.drain()
                            print(role,frame['profile'],store.audit[-1]['route'],flush=True)
                        else: print(role,frame['label'],frame['returncode'],flush=True)
                    process.wait();row['returncode']=process.returncode
                    (root/(role+'.stdout')).write_text(''.join(frames),encoding='utf-8')
                    (root/(role+'.stderr')).write_text(process.stderr.read(),encoding='utf-8')
                    row['raw_archive_sha256']=collect(sandbox,root,role,'/rgec-private/zlib');persist()
                    assert row['returncode']==0,(root/(role+'.stderr')).read_text()[-4000:]
                finally:terminate(sandbox,row)
            reference_data=json.loads((root/'native/evidence.json').read_text())
            for role in ('wrapped-cold','policy-cold','policy-peer-warm'):
                actual=json.loads((root/role/'evidence.json').read_text())
                checks={'output_bytes_match':actual['outputs']==reference_data['outputs'],
                    'native_sources_match':actual['input_sha256']==reference_data['input_sha256'],
                    'phase_status_streams_match':all(all(a[k]==b[k] for k in ('returncode','stdout_sha256','stderr_sha256'))
                        for a,b in zip(actual['phases'],reference_data['phases'])),
                    'actual_roundtrips_match':actual['roundtrips']==reference_data['roundtrips'],
                    'compiler_status_stream_object_match':all(all(a.get(k)==b.get(k) for k in
                        ('returncode','stdout_sha256','stderr_sha256','output_sha256'))
                        for a,b in zip(actual['compiler_actions'],reference_data['compiler_actions']))}
                evidence['comparisons'].append(dict(role=role,**checks));persist()
                assert all(checks.values()),checks
            evidence['store_audit']=store.audit;persist()
    except Exception as error:
        evidence['error']=repr(error);persist();raise
    finally:
        for sandbox,row in zip(sandboxes,evidence['sandboxes']):
            if 'cleanup_returncode' not in row:terminate(sandbox,row)
        persist()


if __name__=='__main__':main(Path(sys.argv[1]))
