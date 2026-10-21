"""Compare genuine native callback admission before/after the gate revision."""
import json
import sys
from pathlib import Path

import modal
from modal_rgec_native import execute, sha, write
from modal_rgec_residual import collect


def main(root, versions=('v16', 'v17'), probe='rgec_incoming_scope_probe.py',
         component_prefix='runs/rgec-modal-residual-state-2026-10-04-'):
    root.mkdir(parents=True, exist_ok=False)
    paths = [Path(__file__), Path('modal_rgec_native.py'), Path('modal_rgec_residual.py'),
        Path('scripts') / probe, Path('scripts/rgec_residual_probe.py'),
        Path('scripts/rgec_backend_probe.py'), Path('scripts/rgec_native_effect_probe.py'),
        Path('scripts/rgec_native_event_probe.py'), Path('src/unauthorized_channels/modal_recipient_entry.py')]
    evidence = {'platform': 'Modal', 'gpu': None, 'cpu': 2, 'memory_mib': 4096,
        'production_shared_policy_enabled': False, 'complete_closure_certified': False,
        'sandboxes': [], 'source_sha256': {str(p): sha(p.read_bytes()) for p in paths}}
    for path in paths: (root / path.name).write_bytes(path.read_bytes())
    try:
        with modal.enable_output(), modal.App('rgec-incoming-callback-scope').run() as app:
            for version in versions:
                prior_root = Path(component_prefix + version)
                prior = json.loads((prior_root / 'evidence.json').read_text())
                assert all(s['returncode'] == 0 and s['cleanup_returncode'] == 137 for s in prior['sandboxes'])
                tools = json.loads((prior_root / 'producer/evidence.json').read_text())['tool_sha256']
                sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app,
                    image=modal.Image.from_id(prior['sandboxes'][0]['image_id']), cpu=2,
                    memory=4096, timeout=1800, block_network=True)
                row = {'phase': version, 'id': sandbox.object_id,
                    'image_id': prior['sandboxes'][0]['image_id'], 'tool_sha256': tools,
                    'frozen_component_root': str(prior_root)}
                evidence['sandboxes'].append(row)
                print(version, sandbox.object_id, flush=True)
                try:
                    code, out, error = execute(sandbox, '/usr/bin/sha256sum', *tools.keys())
                    actual = {line.split()[1]: line.split()[0] for line in out.decode().splitlines()}
                    assert code == 0 and actual == tools, error
                    for path in paths[3:]: write(sandbox, '/' + path.name, (root / path.name).read_bytes())
                    code, out, error = execute(sandbox, '/usr/bin/python3', '-I',
                        '/' + probe, timeout=1200)
                    row['returncode'] = code
                    (root / (version + '.stdout')).write_bytes(out)
                    (root / (version + '.stderr')).write_bytes(error)
                    row['raw_archive_sha256'] = collect(sandbox, root, version)
                    assert code == 0, error[-3000:]
                finally:
                    sandbox.terminate()
                    try: sandbox.wait()
                    except (modal.exception.SandboxTerminatedError, modal.exception.SandboxTimeoutError): pass
                    row['cleanup_returncode'] = sandbox.returncode
    except Exception as error:
        evidence['error'] = str(error)
        raise
    finally:
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main(Path(sys.argv[1]), tuple(sys.argv[2].split(',')) if len(sys.argv) > 2 else ('v16', 'v17'),
         sys.argv[3] if len(sys.argv) > 3 else 'rgec_incoming_scope_probe.py',
         sys.argv[4] if len(sys.argv) > 4 else 'runs/rgec-modal-residual-state-2026-10-04-')
