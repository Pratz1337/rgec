"""Real two-recipient backend reuse with a separate Modal producer and host MACs."""
import json
import shlex
import sys
import tarfile
import uuid
from pathlib import Path

import modal
from modal_rgec_native import execute, sha, write
from unauthorized_channels.backend_recipe_store import BackendRecipeStore, key_files
from unauthorized_channels.modal_broker import ModalBuildSession, TRUSTED


SOURCES = [Path(__file__), Path('src/unauthorized_channels/backend_recipe_store.py'),
    Path('src/unauthorized_channels/modal_broker.py'),
    Path('src/unauthorized_channels/modal_backend_controller.py'),
    Path('src/unauthorized_channels/modal_recipient_entry.py'),
    Path('src/unauthorized_channels/recipient_lease.py'),
    Path('src/unauthorized_channels/recipient_effect.py'),
    Path('scripts/rgec_backend_probe.py'), Path('scripts/rgec_native_effect_probe.py'),
    Path('scripts/rgec_native_event_probe.py'), Path('src/unauthorized_channels/clang_backend_continuation.cpp')]
PROFILES = {'zlib-adler32': ('/src/zlib', 'adler32.c'),
            'zlib-deflate': ('/src/zlib', 'deflate.c'),
            'fuzzer-util': ('/src/libfuzzer', 'FuzzerUtil.cpp')}


def unpack(sandbox, identity, terminal, root):
    archive = root / (identity + '.tar.gz')
    sandbox.filesystem.copy_to_local(TRUSTED + '/requests/' + identity + '.tar.gz', archive)
    assert sha(archive.read_bytes()) == terminal['archive_sha256']
    target = root / identity
    target.mkdir()
    with tarfile.open(archive) as stream:
        for member in stream:
            assert member.isfile() and '/' not in member.name and '\\' not in member.name and member.name not in ('.', '..')
            (target / member.name).write_bytes(stream.extractfile(member).read())
    return json.loads((target / 'trace.json').read_text()), target


def controlled(sandbox, profile, mode, root):
    identity = uuid.uuid4().hex
    code, out, error = execute(sandbox, '/usr/bin/python3', '-I',
        TRUSTED + '/modal_backend_controller.py', profile, identity, mode, timeout=480)
    assert code == 0, error
    terminal = json.loads(out)
    assert terminal['phase'] == 'finished'
    return unpack(sandbox, identity, terminal, root)


def main(root):
    assert sha(SOURCES[-1].read_bytes()) == '74a3f00423e6dee20bad2ab336d61e96c48cb8c9eebd21b72e557f9dd8f2d65b'
    root.mkdir(parents=True, exist_ok=False)
    evidence = {'date': '2026-10-03', 'platform': 'Modal', 'cpu_per_sandbox': 2,
        'memory_mib': 4096, 'gpu': None, 'runtime_network_blocked': True,
        'experimental_shared_reuse': True, 'production_shared_policy_enabled': False,
        'complete_closure_certified': False, 'adaptive_noninterference_proved': False,
        'source_sha256': {str(p): sha(p.read_bytes()) for p in SOURCES},
        'sandboxes': [], 'comparisons': [], 'store_audit': [], 'authority_checks': [], 'request_rejections': []}
    for path in SOURCES:
        (root / path.name).write_bytes(path.read_bytes())
    image = modal.Image.from_id('im-YLBw1X843p0Qaw0NIbkR39')
    for path in SOURCES[3:10]:
        image = image.add_local_file(str(path), TRUSTED + '/' + path.name, copy=True)
    image = image.run_commands('mkdir -p /rgec-trusted/requests /rgec-trusted/actors /workspace/recipient && '
        'chmod 700 /rgec-trusted/requests /rgec-trusted/actors && '
        'chown 65534:65534 /workspace/recipient && chmod 755 /workspace/recipient && '
        'chmod 444 /rgec-trusted/*.py')
    app = modal.App('rgec-authenticated-native-backend')
    sessions = []

    def persist():
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')

    def bind(role):
        sb = modal.Sandbox.create('/bin/sleep', 'infinity', app=app, image=image,
            cpu=2, memory=4096, timeout=1800, block_network=True)
        sessions.append(ModalBuildSession(sb))
        row = {'id': sb.object_id, 'role': role, 'image_id': image.object_id}
        evidence['sandboxes'].append(row); persist()
        code, out, error = execute(sb, '/usr/bin/sha256sum', '/rgec-backend', '/usr/local/bin/clang', '/rgec-backend.cpp')
        assert code == 0, error
        actual = {line.split()[1]: line.split()[0] for line in out.decode().splitlines()}
        assert actual['/rgec-backend'] == '21dcf42d64582bc3120ef75ceacd28a75494e80007d48788cf9e2e062aa9e428'
        assert actual['/usr/local/bin/clang'] == '5d172b74cfd98329f01b3889e0a11f8868a0f514c0cce6f95fc58f3233cc2f38'
        assert actual['/rgec-backend.cpp'] == '74a3f00423e6dee20bad2ab336d61e96c48cb8c9eebd21b72e557f9dd8f2d65b'
        row['tool_sha256'] = actual; persist()
        print('Bound', role, sb.object_id, flush=True)
        return sessions[-1]

    def producer(profile, bound):
        session = bind('separate-producer')
        sb = session._sandbox
        cwd, _ = PROFILES[profile]
        payload = {'cwd': cwd, 'files': [(name, data.hex()) for name, data in key_files(bound)]}
        write(sb, TRUSTED + '/producer-input.json', json.dumps(payload).encode())
        prepare = """import json,os
p=json.load(open('/rgec-trusted/producer-input.json'))
os.chmod('/rgec-trusted/producer-input.json',0o600)
for name,data in p['files']:
 if name.startswith('<') and name.endswith('>'): continue
 path=os.path.abspath(os.path.join(p['cwd'],name)); contents=bytes.fromhex(data)
 assert os.path.realpath(path)==path, path
 if path.startswith(p['cwd']+'/'):
  assert os.path.isfile(path), path
  open(path,'wb').write(contents)
 elif path.startswith('/usr/'):
  assert open(path,'rb').read()==contents, path
 else: raise RuntimeError('unsupported producer input: '+path)
"""
        try:
            code, _, error = execute(sb, '/usr/bin/python3', '-I', '-c', prepare)
            assert code == 0, error
            trace, directory = controlled(sb, profile, 'record', root)
            packet = (directory / 'record.packet').read_bytes()
            origin = {'sandbox_id': sb.object_id, 'image_id': image.object_id,
                'returncode': trace['returncode'], 'reusable': trace['packet_info']['reusable'],
                'artifact_directory': directory.name, 'native_tools_verified': True}
            return packet, origin
        finally:
            sb.terminate()
            try: sb.wait()
            except modal.exception.SandboxTerminatedError: pass
            evidence['sandboxes'][-1]['cleanup_returncode'] = sb.returncode
            persist()

    def setup(session, kind, prior):
        write(session._sandbox, TRUSTED + '/prior.o', prior)
        program = """import os,shutil,sys
sys.path.insert(0,'/rgec-trusted')
from rgec_native_effect_probe import setup
folder='/workspace/recipient'
assert os.path.realpath(folder)==folder
os.chmod(folder,0o755); shutil.rmtree(folder)
setup(folder,sys.argv[1],open('/rgec-trusted/prior.o','rb').read())
"""
        code, _, error = execute(session._sandbox, '/usr/bin/python3', '-I', '-c', program, kind)
        assert code == 0, error

    def compare(label, reference, actual):
        def signature(row):
            result = {}
            for role, path in zip(('output', 'alias', 'target'), row['paths']):
                before, after = row['before'][path], row['after'][path]
                result[role] = {k: v for k, v in after.items() if k not in ('ino', 'mtime_ns', 'ctime_ns')}
                result[role]['inode_changed'] = before.get('ino') != after.get('ino')
            result['held'] = row.get('held_fd_content_sha256')
            result['entries'] = row['directory_entries_after']
            return result
        def queued(row):
            return [(e['mask'], 'temporary' if e['name'].endswith('.tmp') else e['name']) for e in row['events']]
        checks = {'status_and_streams_match': all(reference[k] == actual[k] for k in ('returncode','stdout_sha256','stderr_sha256')),
                  'structural_effects_match': signature(reference) == signature(actual),
                  'queued_event_roles_match': queued(reference) == queued(actual)}
        evidence['comparisons'].append(dict(label=label, reference=reference, actual=actual, **checks))
        persist(); assert all(checks.values()), checks
        print(label, actual['returncode'], actual['receipt'] or 'no query', 'matched', flush=True)

    try:
        with modal.enable_output(), app.run():
            peer, recipient = bind('peer-recipient'), bind('recipient')
            context = {'image_id': image.object_id, 'compiler_sha256': evidence['sandboxes'][0]['tool_sha256']['/usr/local/bin/clang'],
                       'backend_sha256': evidence['sandboxes'][0]['tool_sha256']['/rgec-backend'], 'protocol': 'RGECB1'}
            store = BackendRecipeStore(context, producer)
            for field in ('key','identity','sandbox','image','flags','env','packet'):
                try: recipient.backend_request({'action':'compile','target':'zlib-adler32',field:'override'},root,store)
                except ValueError: evidence['request_rejections'].append(field)
                else: raise AssertionError('accepted override '+field)
            code, _, error = execute(peer._sandbox, '/usr/bin/python3', '-I', '-c',
                "import sys;sys.path.insert(0,'/rgec-trusted');from rgec_backend_probe import run;from rgec_native_effect_probe import FLAGS; "
                "r=run(['/usr/local/bin/clang']+FLAGS+['-fPIC','-c','deflate.c','-o','/workspace/recipient/prior.o'],'/src/zlib');assert r[0]==0,r[2]")
            assert code == 0, error
            peer._sandbox.filesystem.copy_to_local('/workspace/recipient/prior.o',root/'prior.o')
            prior = (root/'prior.o').read_bytes()
            for profile,(cwd,source) in PROFILES.items():
                peer._sandbox.filesystem.copy_to_local(cwd+'/'+source,root/(source+'.original'))
                original = (root/(source+'.original')).read_bytes()
                for variant in ('pristine','backend-error'):
                    edit = original + (b'' if variant=='pristine' else b'\nvoid rgec_actual_backend_error(void) { __asm__("rgec_invalid_instruction"); }\n')
                    (root/(source+'-'+variant+'.source')).write_bytes(edit)
                    for session in (peer,recipient):
                        command='/usr/bin/python3 -I -c '+shlex.quote("import sys;open("+repr(cwd+'/'+source)+",'wb').write(sys.stdin.buffer.read())")
                        result=session.exec(command,input_bytes=edit);assert result.returncode==0,result.stderr
                    for kind in ('regular','readonly-parent'):
                        store.entries.clear()
                        setup(recipient,kind,prior)
                        reference,_=controlled(recipient._sandbox,profile,'native',root)
                        for session,name in ((peer,'cold'),(recipient,'cross-recipient-warm')):
                            setup(session,kind,prior)
                            before=len(store.audit)
                            session.backend_request({'action':'compile','target':profile},root,store)
                            actual=session.captures[-1]
                            assert len(store.audit)==before+1
                            assert store.audit[-1]['route']==('separate-producer-miss' if name=='cold' else 'authenticated-hit')
                            compare(profile+'-'+variant+'-'+kind+'-'+name,reference,actual)
                        evidence['store_audit']=store.audit;persist()
                    if variant=='pristine':
                        setup(recipient,'readonly-output',prior)
                        reference,_=controlled(recipient._sandbox,profile,'native',root)
                        setup(recipient,'readonly-output',prior);before=len(store.audit)
                        recipient.backend_request({'action':'compile','target':profile},root,store)
                        assert len(store.audit)==before and not recipient.captures[-1]['query_emitted']
                        compare(profile+'-readonly-output-before-lookup',reference,recipient.captures[-1])
                    if variant=='backend-error' and profile in ('zlib-adler32','fuzzer-util'):
                        index=next(iter(store.entries));receipt,packet,tag=store.entries[index]
                        store.entries[index]=(receipt,packet[:-1]+bytes([packet[-1]^1]),tag)
                        setup(recipient,'regular',prior);reference,_=controlled(recipient._sandbox,profile,'native',root)
                        setup(recipient,'regular',prior)
                        recipient.backend_request({'action':'compile','target':profile},root,store)
                        assert store.audit[-1]['route']=='recomputed-invalid-entry'
                        compare(profile+'-tampered-packet-recomputed',reference,recipient.captures[-1])
                # Real UID-reduced agent attempts against the controller directory.
                request_id=recipient.captures[-1]['request_id']
                path=TRUSTED+'/requests/'+request_id+'/reply.packet'
                program="import json;checks={};"+"\nfor p in ["+repr(path)+","+repr(cwd+'/'+source)+"]:\n try:\n  f=open(p,'rb');f.read(1);f.close();checks[p]='readable'\n except OSError as e: checks[p]=e.errno\nprint(json.dumps(checks))"
                result=recipient.exec('/usr/bin/python3 -I -c '+shlex.quote(program))
                assert result.returncode==0,result.stderr
                checks=json.loads(result.stdout);assert checks[path]==13 and checks[cwd+'/'+source]=='readable'
                evidence['authority_checks'].append({'profile':profile,'checks':checks});persist()
            evidence['store_audit']=store.audit
            evidence['authenticated_host_records_verified']=True
            persist()
    except Exception as error:
        evidence['error']=str(error);persist();raise
    finally:
        for session in sessions:
            sb=session._sandbox
            sb.terminate()
            try: sb.wait()
            except modal.exception.SandboxTerminatedError: pass
            for row in evidence['sandboxes']:
                if row['id']==sb.object_id:row['cleanup_returncode']=sb.returncode
        persist()


if __name__=='__main__':
    main(Path(sys.argv[1]))
