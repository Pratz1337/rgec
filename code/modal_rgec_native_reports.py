"""Challenge native compiler report state on the exact V23 Modal component."""
import json
from pathlib import Path
import sys

import modal
from modal_rgec_native import execute, sha
from modal_rgec_residual import collect


def main(root):
    prior_root = Path('runs/rgec-modal-generated-slice-2026-10-05-v23-v2')
    prior = json.loads((prior_root / 'evidence.json').read_text())
    tools = prior['sandboxes'][0]['tool_sha256']
    root.mkdir(parents=True, exist_ok=False)
    sources = [Path(__file__), Path('modal_rgec_native.py'), Path('modal_rgec_residual.py'),
        Path('scripts/rgec_native_report_probe.py'), Path('scripts/rgec_residual_probe.py'),
        Path('scripts/rgec_backend_probe.py'), Path('scripts/rgec_native_effect_probe.py'),
        Path('scripts/rgec_native_event_probe.py'), Path('src/unauthorized_channels/modal_recipient_entry.py')]
    sources += [Path('src/unauthorized_channels') / name for name in
                ('clang_backend_continuation.cpp', 'clang_residual_backend.h', 'clang_backend_read_state.h')]
    for path, remote in zip(sources[-3:], ('/rgec-backend.cpp', '/clang_residual_backend.h', '/clang_backend_read_state.h')):
        assert sha(path.read_bytes()) == tools[remote]
    for path in sources: (root / path.name).write_bytes(path.read_bytes())
    evidence = {'platform': 'Modal', 'cpu': 2, 'memory_mib': 4096, 'gpu': None,
        'source_sha256': {str(path): sha(path.read_bytes()) for path in sources},
        'tool_sha256': tools, 'sandboxes': [], 'complete_closure_certified': False,
        'adaptive_noninterference_proved': False, 'production_shared_policy_enabled': False}
    image = modal.Image.from_id(prior['sandboxes'][0]['image_id'])
    for path in sources[3:9]: image = image.add_local_file(str(root / path.name), '/' + path.name, copy=True)
    def persist(): (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    persist(); app = modal.App('rgec-native-report-state-challenge')
    try:
        with modal.enable_output(), app.run():
            sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app, image=image,
                cpu=2, memory=4096, timeout=1800, block_network=True)
            row = {'phase': 'reports', 'id': sandbox.object_id, 'image_id': image.object_id}
            evidence['sandboxes'].append(row); persist()
            print('Native report challenge', sandbox.object_id, flush=True)
            try:
                status, out, error = execute(sandbox, '/usr/bin/sha256sum', *tools.keys())
                actual = {line.split()[1]: line.split()[0] for line in out.decode().splitlines()}
                assert status == 0 and actual == tools, error
                row['tool_sha256'] = actual; persist()
                status, out, error = execute(sandbox, '/usr/bin/python3', '-I',
                    '/rgec_native_report_probe.py', timeout=1500)
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
