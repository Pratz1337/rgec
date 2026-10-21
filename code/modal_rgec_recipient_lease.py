"""Run the real recipient-process lease experiment on Modal CPU workers."""

import json
import sys
from pathlib import Path

import modal

from modal_rgec_native import execute, read, write


def main(root, reference):
    root.mkdir(parents=True, exist_ok=False)
    record = json.loads(reference.read_text())
    assert record['full_native_build_completed'] and record['native_child_returncode'] == 0
    evidence = {'platform': 'Modal', 'reference_snapshot_id': record['configured_snapshot_id'],
                'cpu': 2, 'memory_mib': 4096, 'gpu': None, 'network_blocked': True,
                'shared_reuse_enabled': False, 'full_lease_or_noninterference_certified': False}
    sandbox = None
    try:
        with modal.enable_output(), modal.App('rgec-recipient-lease').run() as app:
            sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app,
                image=modal.Image.from_id(record['configured_snapshot_id']), cpu=2,
                memory=4096, timeout=240, block_network=True)
            evidence['sandbox_id'] = sandbox.object_id
            for path in (Path(__file__), Path('scripts/rgec_recipient_lease_probe.py'),
                         Path('scripts/rgec_native_effect_probe.py'),
                         Path('src/unauthorized_channels/recipient_effect.py'),
                         Path('src/unauthorized_channels/recipient_lease.py')):
                data = path.read_bytes()
                (root / path.name).write_bytes(data)
                write(sandbox, '/' + path.name, data)
            code, out, error = execute(sandbox, '/usr/bin/python3',
                                      '/rgec_recipient_lease_probe.py', timeout=180)
            evidence['returncode'] = code
            (root / 'probe.stdout').write_bytes(out)
            (root / 'probe.stderr').write_bytes(error)
            (root / 'native-lease.json').write_bytes(read(sandbox, '/workspace/recipient-lease/evidence.json'))
            if code == 0:
                for name in ('fixture.stderr', 'leased-native.stdout', 'leased-native.stderr',
                             'recipient-finish.stderr', 'success-output.o', 'held-alias.o',
                             'leased-failure.stdout', 'leased-failure.stderr'):
                    (root / name).write_bytes(read(sandbox, '/workspace/recipient-lease/' + name))
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
