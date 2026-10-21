"""Native generated-function slicing: full compiler baseline and separate workers."""
import ast
import json
import shlex
import sys
from pathlib import Path

import modal
from modal_rgec_native import execute, sha
from modal_rgec_residual import collect


def main(root):
    prior_root = Path('runs/rgec-modal-backend-read-state-2026-10-05-v22')
    prior = json.loads((prior_root / 'evidence.json').read_text())
    tools = json.loads((prior_root / 'producer/evidence.json').read_text())['tool_sha256']
    assert all(row['returncode'] == 0 and row['cleanup_returncode'] == 137 for row in prior['sandboxes'])
    native = [Path('src/unauthorized_channels') / name for name in
        ('clang_backend_continuation.cpp', 'clang_residual_backend.h', 'clang_backend_read_state.h')]
    assert sha(native[0].read_bytes()) == tools['/rgec-backend.cpp']
    assert sha(native[2].read_bytes()) == tools['/clang_backend_read_state.h']
    root.mkdir(parents=True, exist_ok=False)
    sources = [Path(__file__), Path('modal_rgec_native.py'), Path('modal_rgec_residual.py'),
        Path('scripts/rgec_generated_slice_probe.py'), Path('scripts/rgec_residual_probe.py'),
        Path('scripts/rgec_backend_probe.py'), Path('scripts/rgec_native_effect_probe.py'),
        Path('scripts/rgec_native_event_probe.py'), Path('src/unauthorized_channels/modal_recipient_entry.py')] + native
    evidence = {'platform': 'Modal', 'cpu_per_sandbox': 2, 'memory_mib': 4096, 'gpu': None,
        'base_image_id': prior['sandboxes'][0]['image_id'], 'baseline_tool_sha256': tools,
        'source_sha256': {str(path): sha(path.read_bytes()) for path in sources}, 'sandboxes': [],
        'complete_closure_certified': False, 'adaptive_noninterference_proved': False,
        'production_shared_policy_enabled': False, 'runtime_network_blocked': True,
        'scope': 'Real unchanged C/C++ bodies with native diagnostic directives, symbol rewriting, real generated functions, error limits and recipient histories. Component evidence only.'}
    for path in sources: (root / path.name).write_bytes(path.read_bytes())
    # Reuse the exact native static-library build command, not a substitute tool.
    tree = ast.parse((root / 'modal_rgec_residual.py').read_text())
    build = next(ast.literal_eval(node.value) for node in ast.walk(tree) if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == 'build' for target in node.targets))
    build = build[:build.index("os.mkdir('/rgec-driver')")]
    (root / 'native-build.py').write_text(build, encoding='utf-8')
    evidence['build_script_sha256'] = sha((root / 'native-build.py').read_bytes())
    image = modal.Image.from_id(evidence['base_image_id']).run_commands(
        'cp /rgec-backend /rgec-backend-full && cp /clang_residual_backend.h /clang_residual_backend-full.h')
    for path, remote in zip(native, ('/rgec-backend.cpp', '/clang_residual_backend.h', '/clang_backend_read_state.h')):
        image = image.add_local_file(str(root / path.name), remote, copy=True)
    image = image.run_commands('/usr/bin/python3 -I -c ' + shlex.quote('exec(' + repr(build) + ')'))
    for path in sources[3:9]: image = image.add_local_file(str(root / path.name), '/' + path.name, copy=True)
    def persist(): (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    persist(); app = modal.App('rgec-genuine-generated-function-slicing')
    try:
        with modal.enable_output(), app.run():
            for phase in ('capture', 'producer', 'replay-0', 'replay-1', 'replay-2'):
                sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app, image=image,
                    cpu=2, memory=4096, timeout=1800, block_network=True)
                row = {'phase': phase, 'id': sandbox.object_id, 'image_id': image.object_id}
                evidence['sandboxes'].append(row); persist()
                print('Bound native slice worker', phase, sandbox.object_id, flush=True)
                try:
                    checked = ['/usr/local/bin/clang', '/rgec-backend-full', '/clang_residual_backend-full.h',
                        '/rgec-backend', '/rgec-backend.cpp', '/clang_residual_backend.h', '/clang_backend_read_state.h']
                    status, out, error = execute(sandbox, '/usr/bin/sha256sum', *checked)
                    actual = {line.split()[1]: line.split()[0] for line in out.decode().splitlines()}
                    assert status == 0, error
                    assert actual['/rgec-backend-full'] == tools['/rgec-backend']
                    assert actual['/clang_residual_backend-full.h'] == tools['/clang_residual_backend.h']
                    assert actual['/usr/local/bin/clang'] == tools['/usr/local/bin/clang']
                    for path, remote in zip(native, ('/rgec-backend.cpp', '/clang_residual_backend.h', '/clang_backend_read_state.h')):
                        assert actual[remote] == sha((root / path.name).read_bytes())
                    row['tool_sha256'] = actual; persist()
                    if phase != 'capture':
                        for previous in ('capture',) if phase == 'producer' else ('capture', 'producer'):
                            archive = root / previous / 'raw.tar.gz'; remote = '/transfer-' + previous + '.tar.gz'
                            sandbox.filesystem.copy_from_local(archive, remote)
                            status, out, error = execute(sandbox, '/usr/bin/sha256sum', remote)
                            assert status == 0 and out.decode().split()[0] == sha(archive.read_bytes()), error
                            status, out, error = execute(sandbox, '/usr/bin/python3', '-I', '-c',
                                "import os,sys,tarfile; target=sys.argv[2]; os.mkdir(target); "
                                "t=tarfile.open(sys.argv[1]); members=t.getmembers(); "
                                "assert all(m.isfile() and m.name.startswith('raw/') and os.path.basename(m.name)==m.name[4:] for m in members); "
                                "[open(target+'/'+os.path.basename(m.name),'wb').write(t.extractfile(m).read()) for m in members]",
                                remote, '/transfer-' + previous)
                            assert status == 0, error
                    status, out, error = execute(sandbox, '/usr/bin/python3', '-I',
                        '/rgec_generated_slice_probe.py', 'replay' if phase.startswith('replay') else phase, timeout=1500)
                    row['returncode'] = status
                    (root / (phase + '.stdout')).write_bytes(out); (root / (phase + '.stderr')).write_bytes(error)
                    row['raw_archive_sha256'] = collect(sandbox, root, phase); persist()
                    assert status == 0, error[-6000:]
                    print('Completed actual slice phase', phase, flush=True)
                finally:
                    sandbox.terminate()
                    try: sandbox.wait()
                    except (modal.exception.SandboxTerminatedError, modal.exception.SandboxTimeoutError): pass
                    row['cleanup_returncode'] = sandbox.returncode; persist()
    except Exception as error: evidence['error'] = repr(error); persist(); raise
    finally: persist()


if __name__ == '__main__': main(Path(sys.argv[1]))
