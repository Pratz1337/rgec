"""Recover the missing V26 phase on its exact image with durable Modal evidence."""
import json
from pathlib import Path
import sys
import tarfile

import modal
from modal_rgec_native import sha


def main(root):
    original_root = Path('runs/rgec-modal-native-report-admission-2026-10-06-v26')
    original = json.loads((original_root / 'evidence.json').read_bytes())
    old_worker = original['sandboxes'][0]
    old_sandbox = modal.Sandbox.from_id(old_worker['id'])
    assert old_sandbox.poll() == 137
    root.mkdir(parents=True, exist_ok=False)
    for name, expected in original['source_sha256'].items():
        contents = (original_root / Path(name).name).read_bytes()
        assert sha(contents) == expected
        (root / Path(name).name).write_bytes(contents)
    (root / 'native-build.py').write_bytes((original_root / 'native-build.py').read_bytes())
    original_bytes = (original_root / 'evidence.json').read_bytes()
    (root / 'interrupted-attempt-evidence.json').write_bytes(original_bytes)
    prior_root = Path(original['baseline_root']); archive = prior_root / 'reports/raw.tar.gz'
    assert sha(archive.read_bytes()) == original['baseline_archive_sha256']
    packet_hashes = {}
    with tarfile.open(root / 'prior-packets.tar.gz', 'w:gz') as stream:
        for path in sorted((prior_root / 'reports').glob('*.packet')):
            packet_hashes[path.name] = sha(path.read_bytes()); stream.add(path, arcname='raw/' + path.name)
    config = {'prefix': root.name, 'tool_sha256': old_worker['tool_sha256'], 'packet_sha256': packet_hashes}
    (root / 'retention-config.json').write_text(json.dumps(config, indent=2) + '\n')
    for path in (Path(__file__), Path('scripts/rgec_durable_report_worker.py')):
        (root / path.name).write_bytes(path.read_bytes())
    evidence = {k: v for k, v in original.items() if k != 'sandboxes'}
    evidence.update(sandboxes=[], recovered_from_root=str(original_root),
        recovered_from_manifest_sha256=sha(original_bytes), interrupted_worker_observed_returncode=137,
        durable_volume='rgec-native-report-evidence', durable_volume_prefix=root.name,
        prior_packet_sha256=packet_hashes, prior_packet_archive_sha256=sha((root / 'prior-packets.tar.gz').read_bytes()),
        retention_config_sha256=sha((root / 'retention-config.json').read_bytes()))
    evidence['source_sha256'] = dict(original['source_sha256'])
    for path in (Path(__file__), Path('scripts/rgec_durable_report_worker.py')):
        evidence['source_sha256'][str(path)] = sha(path.read_bytes())
    def persist(): (root / 'evidence.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    persist()
    image = modal.Image.from_id(old_worker['image_id'])
    for path, remote in ((root / 'rgec_durable_report_worker.py', '/rgec_durable_report_worker.py'),
        (root / 'prior-packets.tar.gz', '/report-prior-packets.tar.gz'),
        (root / 'retention-config.json', '/report-retention-config.json')):
        image = image.add_local_file(str(path), remote, copy=True)
    volume = modal.Volume.from_name(evidence['durable_volume'], create_if_missing=True)
    app = modal.App('rgec-durable-native-report-recovery')
    with modal.enable_output(), app.run(detach=True):
        sandbox = modal.Sandbox.create('/usr/bin/python3', '-I', '/rgec_durable_report_worker.py',
            app=app, image=image, cpu=2, memory=4096, timeout=1800, block_network=True,
            volumes={'/retained': volume})
        worker = {'phase': 'reports', 'id': sandbox.object_id, 'image_id': image.object_id,
            'tool_sha256': old_worker['tool_sha256'], 'termination_mode': 'native worker entrypoint exits'}
        evidence['sandboxes'].append(worker); persist()
        print('Durable exact-image native report worker', sandbox.object_id, flush=True)
        sandbox.wait()
        worker['cleanup_returncode'] = sandbox.returncode
        result_bytes = b''.join(volume.read_file(root.name + '/result.json'))
        (root / 'durable-result.json').write_bytes(result_bytes)
        result = json.loads(result_bytes)
        assert result['tool_sha256'] == worker['tool_sha256']
        worker['returncode'] = result['returncode']; persist()
        folder = root / 'reports'; folder.mkdir()
        for name, destination in (('raw.tar.gz', folder / 'raw.tar.gz'),
            ('reports.stdout', root / 'reports.stdout'), ('reports.stderr', root / 'reports.stderr')):
            with destination.open('wb') as stream:
                for data in volume.read_file(root.name + '/' + name): stream.write(data)
            assert sha(destination.read_bytes()) == result[name + '_sha256']
        worker['raw_archive_sha256'] = result['raw.tar.gz_sha256']; persist()
        with tarfile.open(folder / 'raw.tar.gz') as stream:
            for member in stream:
                assert member.isfile() and member.name == 'raw/' + Path(member.name).name
                (folder / Path(member.name).name).write_bytes(stream.extractfile(member).read())
        assert worker['returncode'] == worker['cleanup_returncode'] == 0
        print('Durable native evidence collected and worker terminal', flush=True)


if __name__ == '__main__': main(Path(sys.argv[1]))
