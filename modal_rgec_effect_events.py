"""Orchestrate native Linux event-queue evidence on Modal, without local compilation."""

import json
import sys
from pathlib import Path

import modal

from modal_rgec_native import execute, read, write


def main(root, reference):
    root.mkdir(parents=True, exist_ok=False)
    record = json.loads(reference.read_text())
    assert record['full_native_build_completed'] and record['native_child_returncode'] == 0
    evidence = {'platform': 'Modal', 'reference_snapshot_id': record['configured_snapshot_id']}
    sandbox = None
    try:
        app = modal.App('rgec-native-effect-events')
        with modal.enable_output(), app.run():
            sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app,
                image=modal.Image.from_id(record['configured_snapshot_id']),
                cpu=2, memory=4096, timeout=300, block_network=True)
            evidence['sandbox_id'] = sandbox.object_id
            for path in (Path(__file__), Path('scripts/rgec_native_event_probe.py'),
                         Path('scripts/rgec_native_effect_probe.py'),
                         Path('src/unauthorized_channels/recipient_effect.py')):
                data = path.read_bytes()
                (root / path.name).write_bytes(data)
                write(sandbox, '/' + path.name, data)
            code, out, error = execute(sandbox, '/usr/bin/python3', '/rgec_native_event_probe.py')
            evidence['returncode'] = code
            (root / 'probe.stdout').write_bytes(out)
            (root / 'probe.stderr').write_bytes(error)
            (root / 'native-events.json').write_bytes(read(sandbox, '/event-evidence.json'))
            assert code == 0, error[-2000:]
    except Exception as error:
        evidence['error'] = str(error)
        raise
    finally:
        if sandbox:
            sandbox.terminate()
            try:
                sandbox.wait()
            except modal.exception.SandboxTerminatedError:
                pass
            evidence['cleanup_returncode'] = sandbox.returncode
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]))
