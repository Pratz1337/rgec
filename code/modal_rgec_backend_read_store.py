"""Authenticate genuine read-bound native reuse across Modal recipients."""
import json
from pathlib import Path
import sys

import modal
from modal_rgec_native import execute, read, sha, write
from modal_rgec_authenticated_backend import controlled
from modal_rgec_parametric_store import RUNTIME
from unauthorized_channels.backend_recipe_store import BackendRecipeStore, computation_key, key_files
from unauthorized_channels.modal_broker import ModalBuildSession, TRUSTED

PROFILES = {'zlib-adler32-rewrite': ('/src/zlib', 'adler32.c', 'adler32'),
    'zlib-deflate-rewrite': ('/src/zlib', 'deflate.c', 'deflate'),
    'fuzzer-util-rewrite': ('/src/libfuzzer', 'FuzzerUtil.cpp', '_ZN6fuzzer14SimpleFastHashEPKhm')}
MAP = '/workspace/recipient/rewrite-map.yaml'


def main(root, prefix_history=False):
    prior_root = Path('runs/rgec-modal-backend-read-state-2026-10-05-v22')
    prior = json.loads((prior_root / 'evidence.json').read_text())
    assert all(s['returncode'] == 0 and s['cleanup_returncode'] == 137 for s in prior['sandboxes'])
    tools = json.loads((prior_root / 'producer/evidence.json').read_text())['tool_sha256']
    native = [Path('src/unauthorized_channels') / filename for filename in
        ('clang_backend_continuation.cpp', 'clang_residual_backend.h', 'clang_backend_read_state.h')]
    for path, remote in zip(native, ('/rgec-backend.cpp', '/clang_residual_backend.h', '/clang_backend_read_state.h')):
        assert sha(path.read_bytes()) == tools[remote]
    root.mkdir(parents=True, exist_ok=False)
    sources = [Path(__file__), Path('modal_rgec_native.py'), Path('modal_rgec_authenticated_backend.py'),
        Path('modal_rgec_parametric_store.py'), Path('src/unauthorized_channels/backend_recipe_store.py'),
        Path('src/unauthorized_channels/modal_broker.py')] + native + RUNTIME
    evidence = {'platform': 'Modal', 'cpu_per_sandbox': 2, 'memory_mib': 4096, 'gpu': None,
        'workload': 'authentic existing project functions with native diagnostic pragmas and symbol maps',
        'prefix_diagnostic_history_experiment': prefix_history,
        'prefix_history_backend_stack_policy': 'warning' if prefix_history else None,
        'complete_closure_certified': False, 'adaptive_noninterference_proved': False,
        'production_shared_policy_enabled': False, 'runtime_network_blocked': True,
        'sandboxes': [], 'comparisons': [], 'store_audit': [], 'authority_checks': [], 'request_rejections': [],
        'source_sha256': {str(p): sha(p.read_bytes()) for p in sources}}
    for path in sources: (root / path.name).write_bytes(path.read_bytes())
    image = modal.Image.from_id(prior['sandboxes'][0]['image_id'])
    for path in RUNTIME: image = image.add_local_file(str(root / path.name), TRUSTED + '/' + path.name, copy=True)
    image = image.run_commands('mkdir -p /rgec-trusted/requests /rgec-trusted/actors /workspace/recipient && '
        'chmod 700 /rgec-trusted/requests /rgec-trusted/actors && chown 65534:65534 /workspace/recipient && '
        'chmod 755 /workspace/recipient && chmod 444 /rgec-trusted/*.py')
    sessions = []
    def persist(): (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    def bind(role):
        sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app, image=image,
            cpu=2, memory=4096, timeout=7200, block_network=True)
        session = ModalBuildSession(sandbox); sessions.append(session)
        row = {'id': sandbox.object_id, 'role': role, 'image_id': image.object_id}
        evidence['sandboxes'].append(row); persist()
        status, out, error = execute(sandbox, '/usr/bin/sha256sum', *tools.keys())
        actual = {line.split()[1]: line.split()[0] for line in out.decode().splitlines()}
        assert status == 0 and actual == tools, error
        row['tool_sha256'] = actual; persist()
        print('Bound', role, sandbox.object_id, flush=True)
        return session
    def producer(profile, bound):
        reads = []; computation_key(bound, reads)
        assert [path for path, _ in reads] == [MAP]
        session = bind('separate-read-bound-producer'); sandbox = session._sandbox
        write(sandbox, TRUSTED + '/producer.key', bound)
        write(sandbox, TRUSTED + '/producer-input.json', json.dumps({'cwd': PROFILES[profile][0],
            'files': [name for name, _ in key_files(bound)], 'map_bytes': reads[0][1].hex()}).encode())
        program = """import json,os,sys
sys.path.insert(0,'/rgec-trusted')
from rgec_backend_probe import run,packet_info
from rgec_residual_probe import state_input
from rgec_native_effect_probe import sha
p=json.load(open('/rgec-trusted/producer-input.json'));bound=open('/rgec-trusted/producer.key','rb').read()
for path in ('/rgec-trusted/producer.key','/rgec-trusted/producer-input.json'):os.chmod(path,0o600)
protected=set()
for name in p['files']:
 if name.startswith('<'):continue
 path=os.path.realpath(os.path.abspath(os.path.join(p['cwd'],name)))
 assert path.startswith(('/src/zlib/','/src/libfuzzer/','/usr/')),path
 if os.path.isfile(path):os.chmod(path,0);protected.add(path)
mapping='/workspace/recipient/rewrite-map.yaml';open(mapping,'wb').write(bytes.fromhex(p['map_bytes']));os.chmod(mapping,0)
status,out,error=run(['/usr/bin/python3','-I','-c','import sys;open(sys.argv[1],"rb").read()',mapping],p['cwd'])
assert status!=0 and b'PermissionError' in error
open('/rgec-trusted/map-open.stderr','wb').write(error)
args=state_input(bound)['arguments'];status,out,error=run(['/rgec-backend','-cc1']+args,p['cwd'],'record')
open('/rgec-trusted/fresh.control','wb').write(out);open('/rgec-trusted/fresh.stderr','wb').write(error)
assert status==1 and not out
status,out,error=run(['/rgec-backend','--rgec-produce-parametric'],p['cwd'],None,bound)
open('/rgec-trusted/producer.packet','wb').write(out);open('/rgec-trusted/producer.stderr','wb').write(error)
info=packet_info(out);assert info['key_sha256']==sha(bound)
print(json.dumps({'returncode':status,'reusable':info['reusable'],'packet_sha256':sha(out),
 'captured_context_sha256':sha(bound),'computation_key_sha256':info['computation_key_sha256'],
 'protected_files':len(protected)+1,'fresh_frontend_returncode':1,'fresh_frontend_packet':False,
 'map_open_returncode':1,'map_bytes_sha256':sha(bytes.fromhex(p['map_bytes']))}))
"""
        try:
            status, out, error = execute(sandbox, '/usr/bin/python3', '-I', '-c', program, timeout=240)
            assert status == 0, error
            origin = json.loads(out); folder = root / sandbox.object_id; folder.mkdir()
            for filename in ('producer.key', 'producer.packet', 'producer.stderr', 'fresh.control', 'fresh.stderr', 'map-open.stderr'):
                (folder / filename).write_bytes(read(sandbox, TRUSTED + '/' + filename))
            packet = (folder / 'producer.packet').read_bytes()
            assert sha(packet) == origin['packet_sha256']
            origin.update(sandbox_id=sandbox.object_id, image_id=image.object_id, native_tools_verified=True)
            (folder / 'origin.json').write_text(json.dumps(origin, indent=2), encoding='utf-8')
            return packet, origin
        finally:
            sandbox.terminate()
            try: sandbox.wait()
            except (modal.exception.SandboxTerminatedError, modal.exception.SandboxTimeoutError): pass
            next(row for row in evidence['sandboxes'] if row['id'] == sandbox.object_id)['cleanup_returncode'] = sandbox.returncode
            persist()
    def setup(session, contents, prior_object):
        write(session._sandbox, TRUSTED + '/prior.o', prior_object)
        write(session._sandbox, TRUSTED + '/map.yaml', contents)
        status, _, error = execute(session._sandbox, '/usr/bin/python3', '-I', '-c',
            "import os,shutil,sys;sys.path.insert(0,'/rgec-trusted');from rgec_native_effect_probe import setup;"
            "p='/workspace/recipient';os.chmod(p,0o755);shutil.rmtree(p);setup(p,'hardlink',open('/rgec-trusted/prior.o','rb').read());"
            "f=p+'/rewrite-map.yaml';open(f,'wb').write(open('/rgec-trusted/map.yaml','rb').read());os.chmod(f,0o644)")
        assert status == 0, error
    def edit(session, path, data):
        write(session._sandbox, path, data)
        status, _, error = execute(session._sandbox, '/usr/bin/python3', '-I', '-c',
            'import os,sys;os.utime(sys.argv[1],(1641013200,1641013200))', path)
        assert status == 0, error
    def compare(label, reference, actual):
        from scripts.rgec_native_effect_probe import signature
        from scripts.rgec_backend_probe import queue_signature
        checks = {'status_and_streams_match': all(reference[k] == actual[k] for k in ('returncode','stdout_sha256','stderr_sha256')),
            'structural_effects_match': signature(reference) == signature(actual),
            'queued_event_roles_match': queue_signature(reference['events']) == queue_signature(actual['events'])}
        evidence['comparisons'].append(dict(label=label, reference=reference, actual=actual, **checks)); persist()
        assert all(checks.values()), checks
        print(label, actual['returncode'], actual['receipt'] or 'no query', 'matched', flush=True)
    app = modal.App('rgec-authenticated-read-bound-native')
    try:
        with modal.enable_output(), app.run():
            peer, recipient = bind('peer-recipient'), bind('recipient')
            store = BackendRecipeStore({'protocol':'RGECB3','image_id':image.object_id,
                'backend_sha256':tools['/rgec-backend'],'compiler_sha256':tools['/usr/local/bin/clang']}, producer)
            for field in ('key','identity','sandbox','image','flags','env','packet'):
                try: recipient.backend_request({'action':'compile','target':'zlib-adler32-rewrite',field:'override'},root,store)
                except ValueError: evidence['request_rejections'].append(field)
                else: raise AssertionError(field)
            status, _, error = execute(peer._sandbox, '/usr/bin/python3', '-I', '-c',
                "import sys;sys.path.insert(0,'/rgec-trusted');from rgec_backend_probe import run;from rgec_native_effect_probe import FLAGS;"
                "r=run(['/usr/local/bin/clang']+FLAGS+['-fPIC','-c','deflate.c','-o','/workspace/recipient/prior.o'],'/src/zlib');assert r[0]==0,r[2]")
            assert status == 0, error
            fixture = read(peer._sandbox, '/workspace/recipient/prior.o'); (root/'prior.o').write_bytes(fixture)
            for profile, (cwd, source, symbol) in PROFILES.items():
                original = read(peer._sandbox, cwd+'/'+source); (root/(source+'.original')).write_bytes(original)
                edits = {policy: b'#pragma clang diagnostic push\n' +
                    ('#pragma clang diagnostic '+policy.ljust(7)+' "-Wframe-larger-than="\n').encode() +
                    original + b'\n#pragma clang diagnostic pop\n' for policy in ('ignored','warning','error')}
                if prefix_history:
                    edits = {'prefix-'+policy: b'#pragma clang diagnostic push\n' +
                        ('#pragma clang diagnostic '+policy.ljust(7)+' "-W#warnings"\n').encode() +
                        b'#warning recipient native prefix history\n' * 2 +
                        b'#pragma clang diagnostic warning "-Wframe-larger-than="\n' +
                        original + b'\n#pragma clang diagnostic pop\n' for policy in ('ignored','warning')}
                maps = {version: ('function: { source: "'+symbol+'", target: "rgec_actual_map_'+version+'" }\n').encode()
                    for version in ('A','B')}
                for policy,data in edits.items(): (root/(source+'-'+policy+'.source')).write_bytes(data)
                for version,data in maps.items(): (root/(source+'-'+version+'.yaml')).write_bytes(data)
                store.entries.clear()
                sequence = (
                    ('A','ignored',peer,'separate-producer-miss'),('A','error',recipient,'authenticated-hit'),
                    ('B','error',recipient,'separate-producer-miss'),('B','warning',recipient,'authenticated-hit'),
                    ('B','ignored',recipient,'authenticated-hit'),('A','error',recipient,'authenticated-hit'),
                    ('B','error',recipient,'recomputed-invalid-entry'))
                if prefix_history:
                    sequence = (('A','prefix-ignored',peer,'separate-producer-miss'),
                        ('A','prefix-warning',recipient,'authenticated-hit'),
                        ('B','prefix-warning',recipient,'separate-producer-miss'),
                        ('B','prefix-ignored',recipient,'authenticated-hit'))
                for version, policy, actor, route in sequence:
                    if route=='recomputed-invalid-entry':
                        # Corrupt the exact B entry selected by the previous B hit.
                        entry_index = next(index for index in store.entries if index[1] ==
                            next(row['key_sha256'] for row in reversed(store.audit) if row['profile']==profile and row['route']=='authenticated-hit'
                                and row['key_sha256'] != store.audit[-1]['key_sha256']))
                        receipt, packet, tag = store.entries[entry_index]
                        store.entries[entry_index] = (receipt,packet[:-1]+bytes([packet[-1]^1]),tag)
                    edit(actor,cwd+'/'+source,edits[policy]); setup(actor,maps[version],fixture)
                    reference,_=controlled(actor._sandbox,profile,'native',root)
                    setup(actor,maps[version],fixture)
                    actor.backend_request({'action':'compile','target':profile},root,store)
                    actual=actor.captures[-1]
                    evidence['store_audit']=store.audit; persist()
                    assert store.audit[-1]['route']==route,store.audit[-1]
                    compare(profile+'-'+version+'-'+policy+'-'+route,reference,actual)
                if prefix_history:
                    continue
                for cache_state in ('cold','warm'):
                    if cache_state=='cold': saved_entries=dict(store.entries);store.entries.clear()
                    else: store.entries=saved_entries
                    edit(recipient,cwd+'/'+source,edits['error']); setup(recipient,maps['B'],fixture)
                    status,_,error=execute(recipient._sandbox,'/usr/bin/python3','-I','-c','import os;os.unlink("'+MAP+'")')
                    assert status==0,error
                    reference,_=controlled(recipient._sandbox,profile,'native',root)
                    setup(recipient,maps['B'],fixture)
                    status,_,error=execute(recipient._sandbox,'/usr/bin/python3','-I','-c','import os;os.unlink("'+MAP+'")')
                    assert status==0,error
                    count=len(store.audit);recipient.backend_request({'action':'compile','target':profile},root,store)
                    actual=recipient.captures[-1]
                    assert len(store.audit)==count and not actual['query_emitted']
                    compare(profile+'-'+cache_state+'-missing-map-before-query',reference,actual)
                evidence['store_audit']=store.audit;persist()
    except Exception as error:
        evidence['error']=str(error);persist();raise
    finally:
        for session in sessions:
            sandbox=session._sandbox;sandbox.terminate()
            try:sandbox.wait()
            except (modal.exception.SandboxTerminatedError,modal.exception.SandboxTimeoutError):pass
            next(row for row in evidence['sandboxes'] if row['id']==sandbox.object_id)['cleanup_returncode']=sandbox.returncode
        persist()


if __name__=='__main__':main(Path(sys.argv[1]), len(sys.argv)==3 and sys.argv[2]=='prefix-history')
