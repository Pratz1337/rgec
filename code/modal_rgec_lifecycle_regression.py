"""Fresh native V26 producers/recipients; every phase persists independently."""
import json
from pathlib import Path
import sys
import tarfile

import modal
from modal_rgec_native import sha


def main(root):
    prior_root = Path('runs/rgec-modal-native-report-admission-2026-10-07-v26-v2')
    prior = json.loads((prior_root / 'evidence.json').read_bytes())
    worker, = prior['sandboxes']
    assert worker['returncode'] == worker['cleanup_returncode'] == 0
    assert worker['raw_archive_sha256'] == json.loads((prior_root / 'durable-result.json').read_bytes())['raw.tar.gz_sha256']
    assert json.loads((prior_root / 'independent-report-audit.json').read_bytes())['suite_complete']
    native = [Path('src/unauthorized_channels') / name for name in
        ('clang_backend_continuation.cpp', 'clang_residual_backend.h', 'clang_backend_read_state.h')]
    for path, remote in zip(native, ('/rgec-backend.cpp', '/clang_residual_backend.h', '/clang_backend_read_state.h')):
        assert sha(path.read_bytes()) == worker['tool_sha256'][remote]
    sources = [Path(__file__), Path('modal_rgec_native.py'),
        Path('scripts/rgec_durable_slice_worker.py'), Path('scripts/rgec_generated_slice_probe.py'),
        Path('scripts/rgec_residual_probe.py'), Path('scripts/rgec_backend_probe.py'),
        Path('scripts/rgec_native_effect_probe.py'), Path('scripts/rgec_native_event_probe.py'),
        Path('src/unauthorized_channels/modal_recipient_entry.py')] + native
    manifest_path = root / 'evidence.json'
    if not root.exists():
        root.mkdir(parents=True)
        for path in sources: (root / path.name).write_bytes(path.read_bytes())
        build = (prior_root / 'native-build.py').read_bytes()
        (root / 'native-build.py').write_bytes(build)
        evidence = {'platform': 'Modal', 'cpu_per_sandbox': 2, 'memory_mib': 4096, 'gpu': None,
            'base_image_id': worker['image_id'], 'sandboxes': [],
            'baseline_tool_sha256': worker['tool_sha256'],
            'source_sha256': {str(path): sha(path.read_bytes()) for path in sources},
            'build_script_sha256': sha(build), 'native_recompilations': 0,
            'native_report_root': str(prior_root), 'native_report_manifest_sha256': sha((prior_root / 'evidence.json').read_bytes()),
            'durable_volume': 'rgec-native-report-evidence', 'durable_volume_prefix': root.name,
            'complete_closure_certified': False, 'adaptive_noninterference_proved': False,
            'production_shared_policy_enabled': False, 'runtime_network_blocked': True,
            'scope': 'Fresh genuine V26 native captures, sealed full/sliced producers and three native recipient workers; unchanged real C/C++ bodies and native diagnostic directives.'}
        manifest_path.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    evidence = json.loads(manifest_path.read_bytes())
    assert evidence['baseline_tool_sha256'] == worker['tool_sha256']
    current_driver = Path(__file__).read_bytes()
    if sha(current_driver) != evidence['source_sha256'][str(Path(__file__))]:
        name = 'modal_rgec_lifecycle_regression.collection-deferred.py'
        (root / name).write_bytes(current_driver)
        evidence['source_sha256'][name] = sha(current_driver)
        evidence['orchestration_revision'] = {'source': name, 'sha256': sha(current_driver),
            'reason': 'Finish durable native phases before host archive downloads. Existing sandbox IDs resume without new native actions.'}
    for name, expected in evidence['source_sha256'].items():
        assert sha((root / Path(name).name).read_bytes()) == expected
    def persist():
        manifest_path.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    volume = modal.Volume.from_name(evidence['durable_volume'])
    base = modal.Image.from_id(evidence['base_image_id'])
    for path in sources[2:9]:
        base = base.add_local_file(str(root / path.name), '/' + path.name, copy=True)
    app = modal.App('rgec-v26-real-producer-recipient-regression')
    with modal.enable_output(), app.run(detach=True):
        for phase in ('capture', 'producer', 'replay-0', 'replay-1', 'replay-2'):
            row = next((row for row in evidence['sandboxes'] if row['phase'] == phase), None)
            if row is None:
                predecessors = () if phase == 'capture' else ('capture',) if phase == 'producer' else ('capture', 'producer')
                config = {'prefix': root.name, 'tool_sha256': evidence['baseline_tool_sha256'],
                    'transfer_sha256': {p: next(r['raw_archive_sha256'] for r in evidence['sandboxes'] if r['phase'] == p) for p in predecessors}}
                config_path = root / (phase + '-retention-config.json')
                config_path.write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8')
                image = base.add_local_file(str(config_path), '/slice-retention-config.json', copy=True)
                sandbox = modal.Sandbox.create('/usr/bin/python3', '-I', '/rgec_durable_slice_worker.py', phase,
                    app=app, image=image, cpu=2, memory=4096, timeout=1800, block_network=True, volumes={'/retained': volume})
                row = {'phase': phase, 'id': sandbox.object_id, 'image_id': image.object_id,
                    'tool_sha256': config['tool_sha256'], 'retention_config_sha256': sha(config_path.read_bytes()),
                    'termination_mode': 'native worker entrypoint exits'}
                evidence['sandboxes'].append(row); persist()
                print('Started fresh durable native phase', phase, row['id'], flush=True)
            else:
                sandbox = modal.Sandbox.from_id(row['id'])
            sandbox.wait(); row['cleanup_returncode'] = sandbox.returncode; persist()
            remote = root.name + '/' + phase + '/'
            result_bytes = b''.join(volume.read_file(remote + 'result.json'))
            (root / (phase + '-durable-result.json')).write_bytes(result_bytes)
            result = json.loads(result_bytes)
            assert result['tool_sha256'] == row['tool_sha256']
            row['returncode'] = result['returncode']
            row['raw_archive_sha256'] = result['raw.tar.gz_sha256']; persist()
            assert row['returncode'] == row['cleanup_returncode'] == 0
            print('Completed and retained native phase', phase, flush=True)
        for row in evidence['sandboxes']:
            phase = row['phase']; remote = root.name + '/' + phase + '/'
            result = json.loads((root / (phase + '-durable-result.json')).read_bytes())
            folder = root / phase; folder.mkdir(exist_ok=True)
            for name, destination in (('raw.tar.gz', folder / 'raw.tar.gz'),
                ('stdout', root / (phase + '.stdout')), ('stderr', root / (phase + '.stderr'))):
                expected = result[name + '_sha256']
                if destination.exists() and sha(destination.read_bytes()) == expected: continue
                partial = destination.with_name(destination.name + '.partial')
                with partial.open('w+b') as stream:
                    volume.read_file_into_fileobj(remote + name, stream)
                assert sha(partial.read_bytes()) == expected, name
                partial.replace(destination)
            with tarfile.open(folder / 'raw.tar.gz') as stream:
                members = stream.getmembers()
                assert all(m.isfile() and m.name == 'raw/' + Path(m.name).name for m in members)
                assert len({m.name for m in members}) == len(members)
                for member in members:
                    (folder / Path(member.name).name).write_bytes(stream.extractfile(member).read())
            assert row['returncode'] == row['cleanup_returncode'] == 0
            print('Completed, retained and collected native phase', phase, flush=True)


if __name__ == '__main__':
    main(Path(sys.argv[1]))
