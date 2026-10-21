"""Cloud-only native segment feasibility profiles, with retained source bytes."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import modal


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main(root):
    prior_root = Path('runs/rgec-modal-native-stream-admission-2026-10-09-v27')
    prior = json.loads((prior_root / 'evidence.json').read_bytes())
    assert prior['sandbox']['returncode'] == prior['sandbox']['cleanup_returncode'] == 0
    sources = [Path('modal_rgec_native_segments.py'), Path('scripts/rgec_native_segment_profile.py'),
               Path('src/unauthorized_channels/modal_recipient_entry.py')]
    manifest = root / 'evidence.json'
    if not root.exists():
        root.mkdir(parents=True)
        for path in sources: (root / path.name).write_bytes(path.read_bytes())
        (root / 'segment-profile-config.json').write_text(json.dumps({
            'prefix': root.name, 'native_sha256': prior['native_tool_sha256']['/usr/local/bin/clang']},
            indent=2) + '\n', encoding='utf-8')
        evidence = {'platform': 'Modal', 'cpu': 2, 'memory_mib': 6144, 'gpu': None,
            'base_image_id': prior['built_image_id'], 'durable_volume': 'rgec-native-report-evidence',
            'source_sha256': {path.as_posix(): sha(path.read_bytes()) for path in sources},
            'config_sha256': sha((root / 'segment-profile-config.json').read_bytes()),
            'runtime_network_blocked': True, 'sandbox': None,
            'purpose': 'Select useful real native regions before attempting code-bound certification; not cache correctness or performance evidence.',
            'complete_closure_certified': False, 'substantial_novelty_established': False}
        preparation = Path('runs/rgec-modal-native-segment-samples-2026-10-10/evidence.json')
        if preparation.exists():
            prepared = json.loads(preparation.read_bytes())
            assert prepared['base_image_id'] == evidence['base_image_id']
            evidence['prepared_sampler_image_id'] = prepared['sandbox']['image_id']
            evidence['preparation_manifest_sha256'] = sha(preparation.read_bytes())
        manifest.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    evidence = json.loads(manifest.read_bytes())
    for path, expected in evidence['source_sha256'].items():
        assert sha((root / Path(path).name).read_bytes()) == expected
    assert sha((root / 'segment-profile-config.json').read_bytes()) == evidence['config_sha256']

    def persist():
        manifest.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')

    app = modal.App('rgec-genuine-native-segment-profiles')
    volume = modal.Volume.from_name(evidence['durable_volume'])
    with modal.enable_output(), app.run(detach=True):
        if evidence['sandbox'] is None:
            if 'prepared_sampler_image_id' in evidence:
                image = modal.Image.from_id(evidence['prepared_sampler_image_id'])
            else:
                image = modal.Image.from_id(evidence['base_image_id']).run_commands('apt-get update',
                    'DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends google-perftools libgoogle-perftools-dev')
            for path in sources[1:]:
                image = image.add_local_file(str(root / path.name), '/' + path.name, copy=True)
            image = image.add_local_file(str(root / 'segment-profile-config.json'), '/segment-profile-config.json', copy=True)
            sandbox = modal.Sandbox.create('/usr/bin/python3', '-I', '/rgec_native_segment_profile.py',
                app=app, image=image, cpu=2, memory=6144, timeout=3300,
                block_network=True, volumes={'/retained': volume})
            evidence['sandbox'] = {'id': sandbox.object_id, 'image_id': image.object_id,
                'termination_mode': 'native profiling worker exits'}; persist()
            print('Native segment profile worker', sandbox.object_id, flush=True)
        else:
            sandbox = modal.Sandbox.from_id(evidence['sandbox']['id'])
        sandbox.wait(); evidence['sandbox']['cleanup_returncode'] = sandbox.returncode; persist()
        result_bytes = b''.join(volume.read_file(root.name + '/result.json'))
        (root / 'durable-result.json').write_bytes(result_bytes)
        result = json.loads(result_bytes)
        evidence['sandbox']['returncode'] = result['returncode']; persist()
        for name in ('raw.tar.gz', 'stdout', 'stderr'):
            destination = root / name
            if destination.exists() and sha(destination.read_bytes()) == result[name + '_sha256']: continue
            partial = destination.with_name(destination.name + '.partial')
            with partial.open('w+b') as output: volume.read_file_into_fileobj(root.name + '/' + name, output)
            assert sha(partial.read_bytes()) == result[name + '_sha256']
            partial.replace(destination)
        evidence['sandbox']['raw_archive_sha256'] = result['raw.tar.gz_sha256']; persist()
        folder = root / 'raw'; folder.mkdir(exist_ok=True)
        with tarfile.open(root / 'raw.tar.gz') as archive:
            members = archive.getmembers()
            assert len({member.name for member in members}) == len(members)
            for member in members:
                assert member.isfile() and member.name == 'raw/' + Path(member.name).name
                (folder / Path(member.name).name).write_bytes(archive.extractfile(member).read())
        print('Collected native profiles; return codes', result['returncode'], sandbox.returncode, flush=True)
        assert result['returncode'] == sandbox.returncode == 0


if __name__ == '__main__': main(Path(sys.argv[1]))
