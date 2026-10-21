"""Host-authenticated residual reuse across genuine recipient warning policies."""
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path('scripts').resolve()))
sys.path.insert(0, str(Path('src/unauthorized_channels').resolve()))

import modal
from modal_rgec_native import execute, read, sha, write
from modal_rgec_authenticated_backend import controlled
from unauthorized_channels.backend_recipe_store import BackendRecipeStore, key_files
from unauthorized_channels.modal_broker import ModalBuildSession, TRUSTED


PROFILES = {'zlib-adler32-parametric': ('/src/zlib', 'adler32.c'),
            'zlib-deflate-parametric': ('/src/zlib', 'deflate.c'),
            'fuzzer-util-parametric': ('/src/libfuzzer', 'FuzzerUtil.cpp')}
PROFILES.update({name.replace('-parametric', '-nested'): value for name, value in list(PROFILES.items())})
RUNTIME = [Path('src/unauthorized_channels/modal_backend_controller.py'),
    Path('src/unauthorized_channels/modal_recipient_entry.py'), Path('src/unauthorized_channels/recipient_lease.py'),
    Path('src/unauthorized_channels/recipient_effect.py'), Path('scripts/rgec_backend_probe.py'),
    Path('scripts/rgec_native_effect_probe.py'), Path('scripts/rgec_native_event_probe.py'),
    Path('scripts/rgec_residual_probe.py')]


def main(root, native_policy=False, admission=False, compact=False, authority=False):
    prior_run = Path('runs/rgec-modal-residual-state-2026-10-05-v20' if compact else
                     'runs/rgec-modal-residual-state-2026-10-04-v9' if admission
                     else 'runs/rgec-modal-parametric-2026-10-04')
    prior = json.loads((prior_run / 'evidence.json').read_text())
    tools = json.loads((prior_run / 'producer/evidence.json').read_text())['tool_sha256']
    assert all(e['returncode'] == 0 and e['cleanup_returncode'] == 137 for e in prior['sandboxes'])
    assert sha(Path('src/unauthorized_channels/clang_backend_continuation.cpp').read_bytes()) == tools['/rgec-backend.cpp']
    assert sha(Path('src/unauthorized_channels/clang_residual_backend.h').read_bytes()) == tools['/clang_residual_backend.h']
    if compact:
        assert sha(Path('src/unauthorized_channels/clang_backend_read_state.h').read_bytes()) == tools['/clang_backend_read_state.h']
    root.mkdir(parents=True, exist_ok=False)
    sources = [Path(__file__), Path('modal_rgec_authenticated_backend.py'), Path('modal_rgec_native.py'),
        Path('src/unauthorized_channels/backend_recipe_store.py'), Path('src/unauthorized_channels/modal_broker.py'),
        Path('src/unauthorized_channels/clang_backend_continuation.cpp'), Path('src/unauthorized_channels/clang_residual_backend.h'),
        Path('scripts/rgec_parametric_probe.py')] + RUNTIME
    if compact: sources.append(Path('src/unauthorized_channels/clang_backend_read_state.h'))
    evidence = {'date': datetime.now(timezone.utc).date().isoformat(), 'platform': 'Modal', 'gpu': None, 'cpu_per_sandbox': 2,
        'workload': 'native-existing-functions' if native_policy else 'native-source-with-controlled-function-additions',
        'memory_mib': 4096, 'runtime_network_blocked': True, 'production_shared_policy_enabled': False,
        'complete_closure_certified': False, 'parametric_effect_profile_certified': False,
        'adaptive_noninterference_proved': False, 'hybrid_binding_and_native_fallback': admission,
        'producer_context_removed_from_computation_delivery': compact, 'context_capsule_checks': [],
        'sandboxes': [], 'comparisons': [], 'store_audit': [],
        'authority_checks': [], 'request_rejections': [], 'source_sha256': {str(p): sha(p.read_bytes()) for p in sources}}
    for path in sources: (root / path.name).write_bytes(path.read_bytes())
    image = modal.Image.from_id(prior['sandboxes'][0]['image_id'])
    for path in RUNTIME: image = image.add_local_file(str(root / path.name), TRUSTED + '/' + path.name, copy=True)
    image = image.run_commands('mkdir -p /rgec-trusted/requests /rgec-trusted/actors /workspace/recipient && '
        'chmod 700 /rgec-trusted/requests /rgec-trusted/actors && chown 65534:65534 /workspace/recipient && '
        'chmod 755 /workspace/recipient && chmod 444 /rgec-trusted/*.py')
    app = modal.App('rgec-parametric-authenticated-backend')
    sessions = []
    producer_fault = [None]
    def persist(): (root / 'evidence.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    def bind(role):
        sb = modal.Sandbox.create('/bin/sleep', 'infinity', app=app, image=image,
            cpu=2, memory=4096, timeout=7200, block_network=True)
        session = ModalBuildSession(sb); sessions.append(session)
        row = {'role': role, 'id': sb.object_id, 'image_id': image.object_id}
        evidence['sandboxes'].append(row); persist()
        code, out, error = execute(sb, '/usr/bin/sha256sum', *tools.keys())
        actual = {line.split()[1]: line.split()[0] for line in out.decode().splitlines()}
        assert code == 0 and actual == tools, error
        row['tool_sha256'] = actual; persist()
        print('Bound', role, sb.object_id, flush=True)
        return session
    def producer(profile, bound):
        session = bind('separate-captured-ir-producer'); sb = session._sandbox
        write(sb, TRUSTED + '/producer.key', bound)
        write(sb, TRUSTED + '/producer-files.json', json.dumps({'cwd': PROFILES[profile][0],
            'files': [name for name, data in key_files(bound)], 'fault': producer_fault[0],
            'nested_output': profile.endswith('-nested')}).encode())
        program = """import json,os,sys,resource,subprocess
sys.path.insert(0,'/rgec-trusted')
from rgec_backend_probe import run,packet_info
from modal_recipient_entry import ENV,drop
from rgec_residual_probe import state_input
from rgec_native_effect_probe import sha
p=json.load(open('/rgec-trusted/producer-files.json'))
if p['nested_output']:
 os.mkdir('/workspace/recipient/missing');os.chown('/workspace/recipient/missing',65534,65534)
bound=open('/rgec-trusted/producer.key','rb').read()
os.chmod('/rgec-trusted/producer.key',0o600); os.chmod('/rgec-trusted/producer-files.json',0o600)
protected=[]
for name in p['files']:
 if name.startswith('<'): continue
 path=os.path.abspath(os.path.join(p['cwd'],name))
 assert path.startswith(('/src/zlib/','/src/libfuzzer/','/usr/')),path
 if os.path.isfile(path): os.chmod(os.path.realpath(path),0);protected.append(os.path.realpath(path))
args=state_input(bound)['arguments']
status,out,error=run(['/rgec-backend','-cc1']+args,p['cwd'],'record')
open('/rgec-trusted/fresh.control','wb').write(out);open('/rgec-trusted/fresh.stderr','wb').write(error)
assert status==1 and not out
if p['fault']=='address-space':
 def limited():
  resource.setrlimit(resource.RLIMIT_AS,(64*1024*1024,64*1024*1024))
  resource.setrlimit(resource.RLIMIT_CORE,(0,0))
  drop()
 child=subprocess.Popen(['/rgec-backend','--rgec-produce-parametric'],cwd=p['cwd'],env=ENV,
  stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=limited,close_fds=True)
 out,error=child.communicate(bound,timeout=120);status=child.returncode
 assert status not in (0,1) and not out,(status,out[:100],error[:100])
else: status,out,error=run(['/rgec-backend','--rgec-produce-parametric'],p['cwd'],None,bound)
open('/rgec-trusted/producer.packet','wb').write(out);open('/rgec-trusted/producer.stderr','wb').write(error)
info=packet_info(out) if out else {'reusable':False,'computation_key_sha256':None}
if out: assert info['key_sha256']==sha(bound)
print(json.dumps({'returncode':status,'reusable':info['reusable'],'packet_sha256':sha(out),
 'captured_context_sha256':sha(bound),'computation_key_sha256':info['computation_key_sha256'],
 'protected_files':len(set(protected)),'fresh_frontend_returncode':1,'fresh_frontend_packet':False,
 'fault':p['fault'],'address_space_limit_bytes':64*1024*1024 if p['fault'] else None}))
"""
        try:
            code, out, error = execute(sb, '/usr/bin/python3', '-I', '-c', program, timeout=240)
            assert code == 0, error
            origin = json.loads(out); folder = root / sb.object_id; folder.mkdir()
            for name in ('producer.key', 'producer.packet', 'producer.stderr', 'fresh.control', 'fresh.stderr'):
                (folder / name).write_bytes(read(sb, TRUSTED + '/' + name))
            packet = (folder / 'producer.packet').read_bytes()
            assert sha(packet) == origin['packet_sha256'] and sha((folder / 'producer.key').read_bytes()) == sha(bound)
            origin.update(sandbox_id=sb.object_id, image_id=image.object_id, native_tools_verified=True)
            (folder / 'origin.json').write_text(json.dumps(origin, indent=2))
            return packet, origin
        finally:
            sb.terminate()
            try: sb.wait()
            except (modal.exception.SandboxTerminatedError, modal.exception.SandboxTimeoutError): pass
            next(r for r in evidence['sandboxes'] if r['id'] == sb.object_id)['cleanup_returncode'] = sb.returncode
            persist()
    def setup(session, kind, data):
        write(session._sandbox, TRUSTED + '/prior.o', data)
        code, _, error = execute(session._sandbox, '/usr/bin/python3', '-I', '-c',
            "import os,shutil,sys;sys.path.insert(0,'/rgec-trusted');from rgec_native_effect_probe import setup;"
            "p='/workspace/recipient';os.chmod(p,0o755);shutil.rmtree(p);"
            "setup(p,sys.argv[1],open('/rgec-trusted/prior.o','rb').read())", kind)
        assert code == 0, error
    def compare(label, reference, actual):
        from scripts.rgec_native_effect_probe import signature
        from scripts.rgec_backend_probe import queue_signature
        checks = {'status_and_streams_match': all(reference[k] == actual[k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256')),
            'structural_effects_match': signature(reference) == signature(actual),
            'queued_event_roles_match': queue_signature(reference['events']) == queue_signature(actual['events'])}
        evidence['comparisons'].append(dict(label=label, reference=reference, actual=actual, **checks)); persist()
        assert all(checks.values()), checks
        print(label, actual['returncode'], actual['receipt'] or 'no query', 'matched', flush=True)
    def edit(session, path, data):
        command = '/usr/bin/python3 -I -c ' + shlex.quote("import os,sys;p=" + repr(path) +
            ";open(p,'wb').write(sys.stdin.buffer.read());os.utime(p,(1641013200,1641013200))")
        result = session.exec(command, input_bytes=data); assert result.returncode == 0, result.stderr
    try:
        with modal.enable_output(), app.run():
            peer, recipient = bind('peer-recipient'), bind('recipient')
            store = BackendRecipeStore({'protocol': 'RGECB3' if compact else 'RGECB2', 'image_id': image.object_id,
                'backend_sha256': tools['/rgec-backend'], 'compiler_sha256': tools['/usr/local/bin/clang']}, producer)
            for field in ('key', 'identity', 'sandbox', 'image', 'flags', 'env', 'packet'):
                try: recipient.backend_request({'action': 'compile', 'target': 'zlib-adler32-parametric', field: 'override'}, root, store)
                except ValueError: evidence['request_rejections'].append(field)
                else: raise AssertionError(field)
            code, _, error = execute(peer._sandbox, '/usr/bin/python3', '-I', '-c',
                "import sys;sys.path.insert(0,'/rgec-trusted');from rgec_backend_probe import run;from rgec_native_effect_probe import FLAGS;"
                "r=run(['/usr/local/bin/clang']+FLAGS+['-fPIC','-c','deflate.c','-o','/workspace/recipient/prior.o'],'/src/zlib');assert r[0]==0,r[2]")
            assert code == 0, error
            peer._sandbox.filesystem.copy_to_local('/workspace/recipient/prior.o', root / 'prior.o'); fixture = (root / 'prior.o').read_bytes()
            from scripts.rgec_parametric_probe import variants
            suffixes = variants()
            profiles = {name: value for name, value in PROFILES.items()
                        if name.endswith('-nested') == authority}
            for profile, (cwd, source) in profiles.items():
                peer._sandbox.filesystem.copy_to_local(cwd + '/' + source, root / (source + '.original'))
                original = (root / (source + '.original')).read_bytes()
                if authority:
                    def nested_setup(session, fault):
                        setup(session, 'regular', fixture)
                        if fault != 'missing-parent':
                            code, _, error = execute(session._sandbox, '/usr/bin/python3', '-I', '-c',
                                "import os,sys;p='/workspace/recipient/missing';os.mkdir(p);os.chown(p,65534,65534);"
                                "f=p+'/action.o';open(f,'wb').write(open('/rgec-trusted/prior.o','rb').read());"
                                "os.chown(f,65534,65534);os.chmod(f,0o444 if sys.argv[1]=='readonly-output' else 0o600)", fault)
                            assert code == 0, error
                    faults = {}
                    for cache_state in ('cold', 'warm'):
                        store.entries.clear()
                        if cache_state == 'warm':
                            nested_setup(peer, 'valid'); ref, _ = controlled(peer._sandbox, profile, 'native', root)
                            nested_setup(peer, 'valid'); peer.backend_request({'action': 'compile', 'target': profile}, root, store)
                            assert store.audit[-1]['route'] == 'separate-producer-miss'
                            compare(profile + '-warm-peer-prime', ref, peer.captures[-1])
                        for fault in ('missing-parent', 'readonly-output'):
                            nested_setup(recipient, fault); ref, _ = controlled(recipient._sandbox, profile, 'native', root)
                            before = len(store.audit)
                            nested_setup(recipient, fault); recipient.backend_request({'action': 'compile', 'target': profile}, root, store)
                            actual = recipient.captures[-1]
                            assert actual['returncode'] == 1 and not actual['query_emitted'] and len(store.audit) == before
                            compare(profile + '-' + cache_state + '-' + fault, ref, actual)
                            faults[(cache_state, fault)] = actual
                        if cache_state == 'warm':
                            nested_setup(recipient, 'valid'); ref, _ = controlled(recipient._sandbox, profile, 'native', root)
                            nested_setup(recipient, 'valid'); recipient.backend_request({'action': 'compile', 'target': profile}, root, store)
                            assert store.audit[-1]['route'] == 'authenticated-hit'
                            compare(profile + '-valid-recipient-hit', ref, recipient.captures[-1])
                    from scripts.rgec_native_effect_probe import signature
                    from scripts.rgec_backend_probe import queue_signature
                    for fault in ('missing-parent', 'readonly-output'):
                        cold, warm = faults[('cold', fault)], faults[('warm', fault)]
                        assert all(cold[k] == warm[k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256'))
                        assert signature(cold) == signature(warm) and queue_signature(cold['events']) == queue_signature(warm['events'])
                        evidence['authority_checks'].append({'profile': profile, 'fault': fault,
                            'cold_warm_measured_observations_match': True, 'shared_query_emitted': False})
                    evidence['store_audit'] = store.audit; persist(); continue
                edits = {policy: (b'#pragma clang diagnostic push\n' +
                    ('#pragma clang diagnostic ' + policy.ljust(7) + ' "-Wframe-larger-than="\n').encode() +
                    original + b'\n#pragma clang diagnostic pop\n') if native_policy
                    else original + suffixes['ast-policy-' + policy] for policy in ('error', 'ignored', 'warning')}
                for policy, data in edits.items(): (root / (source + '-' + policy + '.source')).write_bytes(data)
                for seed in ('error', 'ignored'):
                    store.entries.clear()
                    edit(peer, cwd + '/' + source, edits[seed])
                    setup(peer, 'hardlink', fixture); ref, _ = controlled(peer._sandbox, profile, 'native', root)
                    setup(peer, 'hardlink', fixture); peer.backend_request({'action': 'compile', 'target': profile}, root, store)
                    compare(profile + '-seed-' + seed + '-miss', ref, peer.captures[-1])
                    assert store.audit[-1]['route'] == 'separate-producer-miss'
                    for policy in ('warning', 'ignored', 'error'):
                        edit(recipient, cwd + '/' + source, edits[policy])
                        setup(recipient, 'hardlink', fixture); ref, _ = controlled(recipient._sandbox, profile, 'native', root)
                        setup(recipient, 'hardlink', fixture); recipient.backend_request({'action': 'compile', 'target': profile}, root, store)
                        assert store.audit[-1]['route'] == 'authenticated-hit'
                        compare(profile + '-seed-' + seed + '-recipient-' + policy, ref, recipient.captures[-1])
                index = next(iter(store.entries)); receipt, packet, tag = store.entries[index]
                store.entries[index] = (receipt, packet[:-1] + bytes([packet[-1] ^ 1]), tag)
                setup(recipient, 'hardlink', fixture); ref, _ = controlled(recipient._sandbox, profile, 'native', root)
                setup(recipient, 'hardlink', fixture); recipient.backend_request({'action': 'compile', 'target': profile}, root, store)
                assert store.audit[-1]['route'] == 'recomputed-invalid-entry'
                compare(profile + '-corruption-recomputed', ref, recipient.captures[-1])
                setup(recipient, 'readonly-output', fixture); ref, _ = controlled(recipient._sandbox, profile, 'native', root)
                before = len(store.audit); setup(recipient, 'readonly-output', fixture)
                recipient.backend_request({'action': 'compile', 'target': profile}, root, store)
                assert len(store.audit) == before and not recipient.captures[-1]['query_emitted']
                compare(profile + '-permission-before-lookup', ref, recipient.captures[-1])
                request = next(r for r in reversed(recipient.captures) if r['query_emitted'])['request_id']
                protected = TRUSTED + '/requests/' + request + '/reply.packet'
                command = '/usr/bin/python3 -I -c ' + shlex.quote("import json;checks={};\nfor p in " +
                    repr([protected, cwd + '/' + source]) + ":\n try:\n  f=open(p,'rb');f.read(1);f.close();checks[p]='readable'\n except OSError as e:checks[p]=e.errno\nprint(json.dumps(checks))")
                reply = recipient.exec(command); assert reply.returncode == 0, reply.stderr
                checks = json.loads(reply.stdout); assert checks[protected] == 13 and checks[cwd + '/' + source] == 'readable'
                evidence['authority_checks'].append({'profile': profile, 'checks': checks})
                if admission:
                    from scripts.rgec_residual_probe import variants as native_variants
                    store.entries.clear()
                    for marker, route in (('A', 'separate-producer-miss'), ('B', 'separate-producer-miss'),
                                          ('B', 'authenticated-hit')):
                        data = ('// Native source context ' + marker + '\n').encode() + original + native_variants()['mapped-backend-error']
                        (root / (source + '-mapped-' + marker + '.source')).write_bytes(data)
                        edit(recipient, cwd + '/' + source, data)
                        setup(recipient, 'hardlink', fixture); ref, _ = controlled(recipient._sandbox, profile, 'native', root)
                        setup(recipient, 'hardlink', fixture); recipient.backend_request({'action': 'compile', 'target': profile}, root, store)
                        assert store.audit[-1]['route'] == route and store.audit[-1]['binding'] == 'full-context'
                        compare(profile + '-mapped-context-' + marker + '-' + route, ref, recipient.captures[-1])
                        request = recipient.captures[-1]['request_id']
                        assert (root / request / 'reply.packet').read_bytes().startswith(b'RGECB1')
                    assert len(store.entries) == 2
                    edit(recipient, cwd + '/' + source, edits['ignored']); store.entries.clear()
                    for label, fault, route in (('cold-producer-memory-failure', 'address-space', 'native-fallback'),
                            ('producer-recovered', None, 'separate-producer-miss'),
                            ('corrupt-entry-producer-memory-failure', 'address-space', 'native-fallback'),
                            ('corrupt-entry-recovered', None, 'recomputed-invalid-entry'),
                            ('recovered-entry-hit', None, 'authenticated-hit')):
                        if label.startswith('corrupt-entry-producer'):
                            index = next(iter(store.entries)); receipt, packet, tag = store.entries[index]
                            store.entries[index] = (receipt, packet[:-1] + bytes([packet[-1] ^ 1]), tag)
                        producer_fault[0] = fault
                        setup(recipient, 'hardlink', fixture); ref, _ = controlled(recipient._sandbox, profile, 'native', root)
                        setup(recipient, 'hardlink', fixture); recipient.backend_request({'action': 'compile', 'target': profile}, root, store)
                        assert store.audit[-1]['route'] == route
                        compare(profile + '-' + label, ref, recipient.captures[-1])
                        assert recipient.captures[-1]['receipt'] == ('RGECF1' if fault else 'RGECH1')
                        if label == 'cold-producer-memory-failure': assert not store.entries
                    producer_fault[0] = None
                if compact:
                    packets = []
                    for context in ('short', 'large-A', 'large-B'):
                        marker = ('RGEC_PRIVATE_SOURCE_CONTEXT_' + context).encode()
                        suffix = b'\n/*' + marker + (b'X' * (4 * 1024 * 1024) if context != 'short' else b'') + b'*/'
                        data = edits['ignored'] + suffix
                        (root / (source + '-context-' + context + '.source')).write_bytes(data)
                        store.entries.clear(); edit(peer, cwd + '/' + source, data)
                        setup(peer, 'hardlink', fixture); ref, _ = controlled(peer._sandbox, profile, 'native', root)
                        setup(peer, 'hardlink', fixture); peer.backend_request({'action': 'compile', 'target': profile}, root, store)
                        compare(profile + '-context-' + context + '-miss', ref, peer.captures[-1])
                        request = peer.captures[-1]['request_id']; delivered = (root / request / 'reply.packet').read_bytes()
                        assert delivered[:6] == b'RGECB3' and marker not in delivered
                        origin = store.audit[-1]['origin']; folder = root / origin['sandbox_id']
                        raw = (folder / 'producer.packet').read_bytes()
                        import struct
                        full_size = struct.unpack_from('<Q', raw, 6)[0]
                        assert delivered == b'RGECB3' + raw[14 + full_size:]
                        packets.append(delivered)
                        edit(recipient, cwd + '/' + source, edits['ignored'])
                        setup(recipient, 'hardlink', fixture); ref, _ = controlled(recipient._sandbox, profile, 'native', root)
                        setup(recipient, 'hardlink', fixture); recipient.backend_request({'action': 'compile', 'target': profile}, root, store)
                        assert store.audit[-1]['route'] == 'authenticated-hit'
                        compare(profile + '-context-' + context + '-recipient-hit', ref, recipient.captures[-1])
                        hit_request = recipient.captures[-1]['request_id']
                        assert (root / hit_request / 'reply.packet').read_bytes() == delivered
                        evidence['context_capsule_checks'].append({'profile': profile, 'context': context,
                            'source_bytes': len(data), 'producer_full_context_bytes': full_size,
                            'delivered_bytes': len(delivered), 'delivered_sha256': sha(delivered),
                            'private_marker_present': False, 'native_effect_program_unchanged': True})
                    assert packets[0] == packets[1] == packets[2]
                evidence['store_audit'] = store.audit; persist()
    except Exception as error:
        evidence['error'] = str(error); persist(); raise
    finally:
        for session in sessions:
            sb = session._sandbox; sb.terminate()
            try: sb.wait()
            except modal.exception.SandboxTerminatedError: pass
            next(r for r in evidence['sandboxes'] if r['id'] == sb.object_id)['cleanup_returncode'] = sb.returncode
        persist()


if __name__ == '__main__':
    mode = sys.argv[2] if len(sys.argv) == 3 else None
    main(Path(sys.argv[1]), mode in ('native-policy', 'admission', 'compact', 'authority'),
         mode in ('admission', 'compact', 'authority'), mode in ('compact', 'authority'), mode == 'authority')
