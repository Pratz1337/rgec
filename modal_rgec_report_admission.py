"""Build native report admission/finish and challenge actual unsafe V23 packets."""
import json
from pathlib import Path
import sys

import modal
from modal_rgec_native import execute, sha
from modal_rgec_residual import collect


def main(root):
    prior_root = Path('runs/rgec-modal-native-report-state-2026-10-06-v23-v3')
    prior = json.loads((prior_root / 'evidence.json').read_bytes())
    baseline = prior['sandboxes'][0]
    assert baseline['returncode'] == 0 and baseline['cleanup_returncode'] == 137
    archive = prior_root / 'reports/raw.tar.gz'
    assert sha(archive.read_bytes()) == baseline['raw_archive_sha256']
    root.mkdir(parents=True, exist_ok=False)
    native = [Path('src/unauthorized_channels') / name for name in
        ('clang_backend_continuation.cpp', 'clang_residual_backend.h', 'clang_backend_read_state.h')]
    sources = [Path(__file__), Path('modal_rgec_native.py'), Path('modal_rgec_residual.py'),
        Path('scripts/rgec_native_report_probe.py'), Path('scripts/rgec_residual_probe.py'),
        Path('scripts/rgec_backend_probe.py'), Path('scripts/rgec_native_effect_probe.py'),
        Path('scripts/rgec_native_event_probe.py'), Path('src/unauthorized_channels/modal_recipient_entry.py')] + native
    for path in sources: (root / path.name).write_bytes(path.read_bytes())
    build = Path('runs/rgec-modal-generated-slice-2026-10-05-v23/native-build.py').read_bytes()
    (root / 'native-build.py').write_bytes(build)
    evidence = {'platform': 'Modal', 'cpu': 2, 'memory_mib': 4096, 'gpu': None,
        'source_sha256': {str(path): sha(path.read_bytes()) for path in sources},
        'build_script_sha256': sha(build), 'baseline_root': str(prior_root),
        'baseline_manifest_sha256': sha((prior_root / 'evidence.json').read_bytes()),
        'baseline_archive_sha256': sha(archive.read_bytes()), 'baseline_tool_sha256': baseline['tool_sha256'],
        'sandboxes': [], 'complete_closure_certified': False, 'runtime_network_blocked': True,
        'adaptive_noninterference_proved': False, 'production_shared_policy_enabled': False}
    image = modal.Image.from_id(baseline['image_id'])
    for path, remote in zip(native, ('/rgec-backend.cpp', '/clang_residual_backend.h', '/clang_backend_read_state.h')):
        image = image.add_local_file(str(root / path.name), remote, copy=True)
    image = image.add_local_file(str(root / 'native-build.py'), '/report-admission-build.py', copy=True)
    image = image.run_commands('/usr/bin/python3 -I /report-admission-build.py')
    for path in sources[3:9]: image = image.add_local_file(str(root / path.name), '/' + path.name, copy=True)
    def persist(): (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    persist(); app = modal.App('rgec-native-report-admission-and-finish')
    try:
        with modal.enable_output(), app.run():
            sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app, image=image,
                cpu=2, memory=4096, timeout=1800, block_network=True)
            row = {'phase': 'reports', 'id': sandbox.object_id, 'image_id': image.object_id}
            evidence['sandboxes'].append(row); persist()
            print('Native report admission challenge', sandbox.object_id, flush=True)
            try:
                status, out, error = execute(sandbox, '/usr/bin/sha256sum', *baseline['tool_sha256'].keys())
                actual = {line.split()[1]: line.split()[0] for line in out.decode().splitlines()}
                assert status == 0, error
                for path, remote in zip(native, ('/rgec-backend.cpp', '/clang_residual_backend.h', '/clang_backend_read_state.h')):
                    assert actual[remote] == sha((root / path.name).read_bytes())
                for remote in ('/usr/local/bin/clang', '/rgec-backend-full', '/clang_residual_backend-full.h'):
                    assert actual[remote] == baseline['tool_sha256'][remote]
                row['tool_sha256'] = actual; persist()
                sandbox.filesystem.copy_from_local(archive, '/transfer-v23.tar.gz')
                status, out, error = execute(sandbox, '/usr/bin/sha256sum', '/transfer-v23.tar.gz')
                assert status == 0 and out.decode().split()[0] == evidence['baseline_archive_sha256'], error
                status, out, error = execute(sandbox, '/usr/bin/python3', '-I', '-c',
                    "import os,tarfile; os.mkdir('/transfer-v23'); t=tarfile.open('/transfer-v23.tar.gz'); "
                    "m=t.getmembers(); assert all(x.isfile() and x.name=='raw/'+os.path.basename(x.name) for x in m); "
                    "[open('/transfer-v23/'+os.path.basename(x.name),'wb').write(t.extractfile(x).read()) for x in m]")
                assert status == 0, error
                status, out, error = execute(sandbox, '/usr/bin/python3', '-I', '/rgec_native_report_probe.py', timeout=1500)
                row['returncode'] = status
                (root / 'reports.stdout').write_bytes(out); (root / 'reports.stderr').write_bytes(error)
                row['raw_archive_sha256'] = collect(sandbox, root, 'reports'); persist()
                assert status == 0, error[-5000:]
            finally:
                sandbox.terminate()
                try: sandbox.wait()
                except (modal.exception.SandboxTerminatedError, modal.exception.SandboxTimeoutError): pass
                row['cleanup_returncode'] = sandbox.returncode; persist()
    except Exception as error: evidence['error'] = repr(error); persist(); raise
    finally: persist()


if __name__ == '__main__': main(Path(sys.argv[1]))
