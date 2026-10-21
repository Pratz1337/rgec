"""Audit completed native workers beside their retained bytes, without reruns."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import modal


def sha(data): return hashlib.sha256(data).hexdigest()


def main(root, audit_name):
    raw = (root / 'evidence.json').read_bytes(); manifest = json.loads(raw)
    assert len(manifest['sandboxes']) == 5
    assert all(w['returncode'] == w['cleanup_returncode'] == 0 for w in manifest['sandboxes'])
    folder = root / audit_name; folder.mkdir(exist_ok=False)
    auditor = Path('scripts/audit_rgec_generated_slice.py')
    worker_source = Path('scripts/rgec_modal_slice_audit.py')
    for source in (Path(__file__), auditor, worker_source):
        (folder / source.name).write_bytes(source.read_bytes())
    names = {Path(path).name for path in manifest['source_sha256']}
    names.update(('evidence.json', 'native-build.py'))
    for row in manifest['sandboxes']:
        names.update((row['phase'] + '-retention-config.json', row['phase'] + '-durable-result.json'))
    archive = folder / 'inputs.tar.gz'
    with tarfile.open(archive, 'w:gz') as stream:
        for name in sorted(names): stream.add(root / name, arcname='raw/' + name)
    config = {'prefix': root.name, 'audit_name': audit_name, 'manifest_sha256': sha(raw),
        'auditor_sha256': sha(auditor.read_bytes()), 'inputs_archive_sha256': sha(archive.read_bytes())}
    config_path = folder / 'config.json'; config_path.write_text(json.dumps(config, indent=2) + '\n')
    image = modal.Image.debian_slim(python_version='3.11')
    for local, remote in ((auditor, '/audit_rgec_generated_slice.py'),
        (worker_source, '/rgec_modal_slice_audit.py'), (archive, '/slice-audit-inputs.tar.gz'),
        (config_path, '/slice-audit-config.json'),
        (Path(manifest['native_report_root']) / 'evidence.json', '/' + manifest['native_report_root'].replace('\\', '/') + '/evidence.json')):
        image = image.add_local_file(str(local), remote, copy=True)
    volume = modal.Volume.from_name(manifest['durable_volume'])
    evidence = dict(config, worker_source_sha256=sha(worker_source.read_bytes()),
        controller_sha256=sha(Path(__file__).read_bytes()), native_compiler_actions=0)
    evidence_path = folder / 'evidence.json'
    def persist(): evidence_path.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    persist()
    app = modal.App('rgec-v26-independent-durable-byte-audit')
    with modal.enable_output(), app.run(detach=True):
        sandbox = modal.Sandbox.create('python3', '-I', '/rgec_modal_slice_audit.py',
            app=app, image=image, cpu=2, memory=4096, timeout=1800, block_network=True, volumes={'/retained':volume})
        evidence.update(sandbox_id=sandbox.object_id, image_id=image.object_id); persist()
        print('Independent cloud byte auditor', sandbox.object_id, flush=True)
        sandbox.wait(); evidence['cleanup_returncode'] = sandbox.returncode; persist()
        remote = root.name + '/' + audit_name + '/'
        result_bytes = b''.join(volume.read_file(remote + 'result.json'))
        (folder / 'result.json').write_bytes(result_bytes); result = json.loads(result_bytes)
        evidence['returncode'] = result['returncode']; persist()
        for name in ('stdout', 'stderr'):
            (folder / name).write_bytes(b''.join(volume.read_file(remote + name)))
        assert result['input_manifest_sha256'] == config['manifest_sha256']
        assert result['auditor_sha256'] == config['auditor_sha256']
        assert result['returncode'] == evidence['cleanup_returncode'] == 0, result
        audit_bytes = b''.join(volume.read_file(remote + 'independent-slice-audit.json'))
        assert sha(audit_bytes) == result['audit_sha256']
        (root / 'independent-slice-audit.json').write_bytes(audit_bytes)
        evidence['audit_sha256'] = result['audit_sha256']; persist()
        audit = json.loads(audit_bytes)
        print(json.dumps({key:audit[key] for key in ('manifest_sha256','native_observations','native_reference_pairs','comparison_results')}))


if __name__ == '__main__': main(Path(sys.argv[1]), sys.argv[2])
