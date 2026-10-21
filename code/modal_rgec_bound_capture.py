"""Real host-bound Modal capture/publication and unprivileged native builds."""

import concurrent.futures
import ast
import importlib.util
import json
import shlex
import sys
import threading
import time
from pathlib import Path

import modal

from modal_rgec_native import app, compiler_action, execute, read, sha, write
from unauthorized_channels.modal_broker import ModalBuildSession


SOURCES = [Path(__file__), Path('src/unauthorized_channels/modal_broker.py'),
    Path('src/unauthorized_channels/modal_recipient_entry.py'),
    Path('src/unauthorized_channels/modal_recipient_capture.py'),
    Path('src/unauthorized_channels/recipient_lease.py'),
    Path('src/unauthorized_channels/recipient_effect.py'),
    Path('src/unauthorized_channels/compiler_worker_chroot.py'),
    Path('scripts/rgec_recipient_lease_probe.py'),
    Path('scripts/validate_rgec_build_boundary.py'),
    Path('modal_rgec_native.py'), Path('src/unauthorized_channels/compiler_worker.py')]
FLAGS = ['-O1', '-fno-omit-frame-pointer', '-gline-tables-only',
    '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION', '-fsanitize=address',
    '-fsanitize-address-use-after-scope', '-fsanitize=fuzzer-no-link']


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(root, reference, observer_record, *, full_only=False):
    root.mkdir(parents=True, exist_ok=False)
    parent, observer = json.loads(reference.read_text()), json.loads(observer_record.read_text())
    assert parent['full_native_build_completed'] and parent['native_child_returncode'] == 0
    assert observer['returncode'] == 0 and observer['reference_snapshot_id'] == parent['configured_snapshot_id']
    evidence = {'date': '2026-10-03', 'platform': 'Modal', 'gpu': None,
        'cpu': 4, 'memory_mib': 8192, 'network_blocked': True, 'shared_reuse_enabled': False,
        'complete_closure_certified': False, 'captures': [], 'builds': [], 'commands': [],
        'sandboxes': [], 'request_rejections': [], 'source_sha256': {str(p): sha(p.read_bytes()) for p in SOURCES}}
    for path in SOURCES:
        (root / path.name).write_bytes(path.read_bytes())
    image = modal.Image.from_id(observer['plugin_image_id'])
    for path in SOURCES[2:6]:
        image = image.add_local_file(str(path), '/rgec-trusted/' + path.name, copy=True)
    image = image.run_commands('cp /usr/lib/libFuzzingEngine.a /work/libFuzzingEngine.a && '
        'chown -R 65534:65534 /src /work /out && '
        'chmod 755 /workspace && mkdir -p /workspace/recipient /rgec-trusted/requests '
        '/rgec-trusted/actors /rgec-trusted/cache && '
        'chown 65534:65534 /workspace/recipient && chmod 755 /rgec-trusted && '
        'chmod 700 /rgec-trusted/requests /rgec-trusted/actors /rgec-trusted/cache && '
        'chmod 444 /rgec-trusted/*.py').env({
            'LIB_FUZZING_ENGINE': '/work/libFuzzingEngine.a', 'LIBRARY_PATH': '/work'})
    boundary = load(Path('scripts/validate_rgec_build_boundary.py'), 'boundary_probe')
    actor_tree = ast.parse(Path('scripts/rgec_recipient_lease_probe.py').read_text())
    actor_template = next(ast.literal_eval(node.value) for node in actor_tree.body
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and
            target.id == 'ACTOR' for target in node.targets))
    sessions = []

    def persist():
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')

    def bind():
        sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app, image=image,
            cpu=4, memory=8192, timeout=2400, block_network=True)
        sessions.append(ModalBuildSession(sandbox))
        evidence['sandboxes'].append({'id': sandbox.object_id, 'image': image.object_id})
        persist()
        print('Created Modal recipient:', sandbox.object_id, flush=True)
        code, actual, error = execute(sandbox, '/usr/bin/sha256sum', '/rgec-closure.so')
        assert code == 0 and actual.decode().split()[0] == observer['plugin_binary_sha256'], error
        cached = Path('runs/rgec-modal-native-2026-10-02-v4/zlib-adler32.native.o').read_bytes()
        write(sandbox, '/rgec-trusted/cache/native.o', cached)
        code, _, error = execute(sandbox, '/bin/chmod', '600', '/rgec-trusted/cache/native.o')
        assert code == 0, error
        evidence['sandboxes'][-1]['actual_protected_object_sha256'] = sha(cached)
        persist()
        print('Bound Modal recipient:', sandbox.object_id, flush=True)
        return sessions[-1]

    def command(session, label, text, expected=0, timeout=180):
        result = session.exec(text, timeout=timeout)
        (root / (label + '.stdout')).write_bytes(result.stdout)
        (root / (label + '.stderr')).write_bytes(result.stderr)
        evidence['commands'].append({'label': label, 'command': text, 'returncode': result.returncode,
            'stdout_sha256': sha(result.stdout), 'stderr_sha256': sha(result.stderr)})
        persist()
        if expected is not None:
            assert result.returncode == expected, result.stderr[-1500:]
        return result

    def put(session, label, path, data):
        text = '/usr/bin/python3 -I -c ' + shlex.quote(
            "import sys; open(" + repr(path) + ",'wb').write(sys.stdin.buffer.read())")
        result = session.exec(text, input_bytes=data)
        (root / (label + '.stdout')).write_bytes(result.stdout)
        (root / (label + '.stderr')).write_bytes(result.stderr)
        evidence['commands'].append({'label': label, 'command': text, 'returncode': result.returncode,
            'input_bytes': len(data), 'input_sha256': sha(data),
            'stdout_sha256': sha(result.stdout), 'stderr_sha256': sha(result.stderr)})
        persist()
        assert result.returncode == 0, result.stderr[-1500:]

    def request(session, label, target):
        result = session.request({'action': 'compile', 'target': target}, root, compiler_action)
        row = dict(session.captures[-1], label=label)
        evidence['captures'].append(row)
        persist()
        print('Captured action:', label, 'candidate', row['candidate'], 'rc', result.returncode, flush=True)
        return result, row

    try:
        with modal.enable_output(), app.run():
            if not full_only:
                session = bind()
                for field, value in [('sandbox', 'another-recipient'), ('identity', 'peer'),
                        ('image', 'other-image'), ('key', 'guessed-key'), ('env', {'CC': 'modified'}),
                        ('flags', ['-Xclang', '-load']), ('command', 'arbitrary-host-command')]:
                    payload = {'action': 'compile', 'target': 'zlib-adler32', field: value}
                    try:
                        session.request(payload, root, compiler_action)
                    except ValueError as error:
                        evidence['request_rejections'].append({'field': field, 'error': str(error)})
                    else:
                        raise AssertionError('accepted override ' + field)
                original = read(session._sandbox, '/src/zlib/adler32.c')
                native_objects = {}
                profiles = [('zlib-adler32', '/src/zlib', 'adler32.c', [], FLAGS + ['-fPIC']),
                    ('zlib-deflate', '/src/zlib', 'deflate.c', [], FLAGS + ['-fPIC']),
                    ('graphicsmagick-png', '/src/graphicsmagick', 'coders/png.c',
                     ['-DHAVE_CONFIG_H', '-I.', '-I.', '-I/work/include'], FLAGS + ['-Wall'])]
                for label, cwd, source, pp, flags in profiles:
                    native_command = 'cd ' + shlex.quote(cwd) + ' && ' + shlex.join(
                        ['/usr/local/bin/clang'] + pp + flags + ['-c', source, '-o', '/workspace/recipient/reference.o'])
                    reference_result = command(session, label + '-native', native_command)
                    native_objects[label] = read(session._sandbox, '/workspace/recipient/reference.o')
                    (root / (label + '.native.o')).write_bytes(native_objects[label])
                    result, row = request(session, label, label)
                    row['equals_native_object'] = row['object_sha256'] == sha(native_objects[label])
                    row['equals_native_streams'] = result.stdout == reference_result.stdout and result.stderr == reference_result.stderr
                    assert result.returncode == 0 and row['equals_native_object'] and row['equals_native_streams']
                    persist()
                edited = original.replace(b'if (buf == Z_NULL)\n        return 1L;',
                                          b'if (buf == Z_NULL)\n        return 7L;')
                assert edited != original
                put(session, 'semantic-edit', '/src/zlib/adler32.c', edited)
                native_command = 'cd /src/zlib && ' + shlex.join(['/usr/local/bin/clang'] + FLAGS +
                    ['-fPIC', '-c', 'adler32.c', '-o', '/workspace/recipient/reference.o'])
                baseline = command(session, 'semantic-edit-native', native_command)
                edited_object = read(session._sandbox, '/workspace/recipient/reference.o')
                result, row = request(session, 'semantic-edit', 'zlib-adler32')
                row['semantic_edit_changes_object'] = sha(edited_object) != sha(native_objects['zlib-adler32'])
                row['equals_native_object'] = row['object_sha256'] == sha(edited_object)
                row['equals_native_streams'] = result.stdout == baseline.stdout and result.stderr == baseline.stderr
                assert row['semantic_edit_changes_object'] and row['equals_native_object'] and row['equals_native_streams']
                put(session, 'restore-after-semantic-edit', '/src/zlib/adler32.c', original)
                clock = original + b'\n#pragma clang diagnostic ignored "-Wdate-time"\nconst char rgec_request_clock[] = __TIME__;\n'
                put(session, 'suppressed-clock-edit', '/src/zlib/adler32.c', clock)
                result, row = request(session, 'suppressed-clock', 'zlib-adler32')
                assert not row['candidate'] and row['sealed_backend'] is None and result.returncode == 0
                assert '__TIME__' in row['observation']['macro_dependencies']
                put(session, 'restore-after-clock', '/src/zlib/adler32.c', original)
                put(session, 'readonly-prior-object', '/workspace/recipient/action.o', native_objects['zlib-deflate'])
                command(session, 'readonly-mode', 'chmod 444 /workspace/recipient/action.o')
                native_same_path = 'cd /src/zlib && ' + shlex.join(['/usr/local/bin/clang'] + FLAGS +
                    ['-fPIC', '-c', 'adler32.c', '-o', '/workspace/recipient/action.o'])
                baseline = command(session, 'readonly-native', native_same_path, expected=1)
                result, row = request(session, 'readonly-output', 'zlib-adler32')
                row['equals_native_failure_streams'] = result.stdout == baseline.stdout and result.stderr == baseline.stderr
                assert result.returncode == 1 and row['equals_native_failure_streams'] and not row['candidate']
                command(session, 'writable-mode', 'chmod 644 /workspace/recipient/action.o')
                put(session, 'error-edit', '/src/zlib/adler32.c', original + b'\n#error RGEC real bound native error\n')
                baseline = command(session, 'failure-native', native_same_path, expected=1)
                put(session, 'failure-prior-object', '/workspace/recipient/action.o', native_objects['zlib-deflate'])
                result, row = request(session, 'source-failure', 'zlib-adler32')
                row['equals_native_failure_streams'] = result.stdout == baseline.stdout and result.stderr == baseline.stderr
                assert result.returncode == 1 and row['equals_native_failure_streams'] and not row['candidate']
                command(session, 'failure-output-removed', 'test ! -e /workspace/recipient/action.o')
                put(session, 'restore-after-error', '/src/zlib/adler32.c', original)
                put(session, 'daemon-held-native-object', '/workspace/recipient/action.o', native_objects['zlib-deflate'])
                actor = actor_template.replace("root+'/zlib/adler32.c'", "'/src/zlib/adler32.c'")
                command(session, 'spawn-real-background-writer', '/usr/bin/python3 -I -c ' +
                    shlex.quote(actor) + ' /workspace/recipient daemon >/dev/null 2>&1')
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    pending = pool.submit(request, session, 'writer-bound-capture', 'zlib-adler32')
                    deadline = time.monotonic() + 30
                    while session.current_capture is None:
                        assert time.monotonic() < deadline and not pending.done()
                        time.sleep(0.02)
                    capture = session.current_capture
                    assert session._gate.locked() and capture['stopped_actors']
                    assert session._controller.poll() is None
                    entered = threading.Event()
                    def queued_exec():
                        entered.set()
                        return command(session, 'queued-agent-exec', 'printf executed > /workspace/recipient/queued-exec')
                    queued = pool.submit(queued_exec)
                    assert entered.wait(5)
                    code, observed, error = execute(session._sandbox, '/usr/bin/python3', '-I', '-c',
                        "import json,os; print(json.dumps({'queued_file_exists':os.path.exists('/workspace/recipient/queued-exec')}))")
                    assert code == 0, error
                    observation = json.loads(observed)
                    evidence['exec_gate_observation'] = dict(observation,
                        gate_locked=session._gate.locked(), queued_call_complete=queued.done(),
                        live_controller_returncode=session._controller.poll())
                    assert not observation['queued_file_exists'] and not queued.done()
                    result, row = pending.result()
                    assert result.returncode == 0 and row['object_sha256'] == sha(native_objects['zlib-adler32'])
                    assert queued.result().returncode == 0
                    evidence['exec_gate_observation']['queued_call_completed_after_publication'] = True
                session.close()
            # The whole native script stays private; use a fresh recipient so
            # the writer compatibility fixture cannot alter this build.
            full = bind()
            for label in ('pristine', 'edited-script-wrapper-plugin'):
                if label.startswith('edited'):
                    store = '/rgec-trusted/cache/native.o'
                    probe = boundary.access_probe(store).replace('/workspace/', '/workspace/recipient/')
                    plugin = boundary.compiler_plugin(store).replace('/workspace/', '/workspace/recipient/')
                    put(full, 'write-access-probe', '/workspace/recipient/authority_probe.py', probe.encode())
                    put(full, 'write-agent-plugin', '/workspace/recipient/authority_probe.c', plugin.encode())
                    command(full, 'store-symlink', 'ln -s ' + shlex.quote(store) + ' /workspace/recipient/store-alias')
                    command(full, 'compile-agent-plugin', 'clang -shared -fPIC /workspace/recipient/authority_probe.c -o /workspace/recipient/authority_probe.so')
                    command(full, 'wrapper-directory', 'mkdir /workspace/recipient/compiler-wrappers')
                    for compiler in ('clang', 'clang++'):
                        wrapper = '#!/bin/sh\nif test ! -e /workspace/recipient/wrapper-seen; then\n' \
                            '/usr/bin/python3 -I /workspace/recipient/authority_probe.py compiler-wrapper || exit 120\n' \
                            'touch /workspace/recipient/wrapper-seen\nfi\nexec /usr/local/bin/' + compiler + \
                            ' -Xclang -load -Xclang /workspace/recipient/authority_probe.so "$@"\n'
                        put(full, 'write-wrapper-' + compiler, '/workspace/recipient/compiler-wrappers/' + compiler, wrapper.encode())
                    command(full, 'enable-wrappers', 'chmod +x /workspace/recipient/compiler-wrappers/*')
                    build_script = read(full._sandbox, '/src/build.sh')
                    hook = b'#!/bin/bash\nset -e\n/usr/bin/python3 -I /workspace/recipient/authority_probe.py edited-build-script\n' \
                        b"/bin/sh -c '/usr/bin/python3 -I /workspace/recipient/authority_probe.py nested-subprocess'\n" \
                        b'export PATH=/workspace/recipient/compiler-wrappers:$PATH\n'
                    put(full, 'edit-native-build-script', '/src/build.sh', hook + build_script)
                command(full, label + '-remove-prebuilt', 'rm -- /out/coder_MNG_fuzzer && test ! -e /out/coder_MNG_fuzzer')
                print('Full unprivileged native build:', label, flush=True)
                started = time.perf_counter()
                result = full.build({'action': 'compile'})
                (root / (label + '.build.stdout')).write_bytes(result.stdout)
                (root / (label + '.build.stderr')).write_bytes(result.stderr)
                row = {'label': label, 'returncode': result.returncode, 'seconds': time.perf_counter() - started,
                    'prebuilt_fuzzer_removed': True}
                evidence['builds'].append(row)
                persist()
                assert result.returncode == 0, result.stderr[-2000:]
                checked = command(full, label + '-fuzzer-identity', 'test -f /out/coder_MNG_fuzzer && test ! -L /out/coder_MNG_fuzzer && sha256sum /out/coder_MNG_fuzzer')
                row['fuzzer_sha256'] = checked.stdout.decode().split()[0]
                row['equals_earlier_native_fuzzer'] = row['fuzzer_sha256'] == parent['fuzzer_sha256']
                if label == 'pristine':
                    regenerated = row['fuzzer_sha256']
                else:
                    row['equals_current_pristine_fuzzer'] = row['fuzzer_sha256'] == regenerated
                    assert row['equals_current_pristine_fuzzer']
                print('Native target regenerated:', label, row['fuzzer_sha256'], flush=True)
                persist()
            for name in ('access.jsonl', 'plugin.json'):
                result = command(full, 'collect-' + name, 'cat /workspace/recipient/' + name)
                (root / name).write_bytes(result.stdout)
            evidence['access_checks'] = [json.loads(line) for line in (root / 'access.jsonl').read_text().splitlines()]
            evidence['plugin_check'] = json.loads((root / 'plugin.json').read_text())
            for row in evidence['access_checks']:
                assert row['uid'] == 65534 and not any(row['opened'].values()) and row['own_readable'] and row['own_writable']
                assert not any(int(v, 16) for v in row['caps'].values()) and row['no_new_privs'] == 1
            row = evidence['plugin_check']
            assert not row['read_open'] and not row['write_open'] and row['own_read_open'] and not row['effective_caps'] and row['no_new_privs'] == 1
            for session in sessions:
                audits = {identity: json.loads(read(session._sandbox, '/rgec-trusted/actors/' + identity + '.json'))
                          for identity in session.actor_ids if session._sandbox.poll() is None}
                evidence['sandboxes'][sessions.index(session)]['actor_audits'] = audits
                if session._sandbox.poll() is None:
                    assert sha(read(session._sandbox, '/rgec-trusted/cache/native.o')) == evidence['sandboxes'][sessions.index(session)]['actual_protected_object_sha256']
    except Exception as error:
        evidence['error'] = str(error)
        raise
    finally:
        for session in sessions:
            session.close()
            try:
                session._sandbox.wait()
            except modal.exception.SandboxTerminatedError:
                pass
            evidence['sandboxes'][sessions.index(session)]['cleanup_returncode'] = session._sandbox.returncode
        persist()


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]),
         full_only='--full-only' in sys.argv[4:])
