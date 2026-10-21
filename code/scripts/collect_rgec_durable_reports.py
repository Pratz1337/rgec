"""Collect an already completed native report worker without executing it again."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import modal


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main(root):
    manifest_path = root / 'evidence.json'
    manifest = json.loads(manifest_path.read_bytes())
    result = json.loads((root / 'durable-result.json').read_bytes())
    worker, = manifest['sandboxes']
    assert worker['returncode'] == worker['cleanup_returncode'] == result['returncode'] == 0
    assert worker['tool_sha256'] == result['tool_sha256']
    volume = modal.Volume.from_name(manifest['durable_volume'])
    folder = root / 'reports'
    folder.mkdir(exist_ok=True)
    for name, destination in (('raw.tar.gz', folder / 'raw.tar.gz'),
        ('reports.stdout', root / 'reports.stdout'), ('reports.stderr', root / 'reports.stderr')):
        expected = result[name + '_sha256']
        if destination.exists() and digest(destination) == expected:
            continue
        partial = destination.with_name(destination.name + '.partial')
        with partial.open('w+b') as stream:
            size = volume.read_file_into_fileobj(manifest['durable_volume_prefix'] + '/' + name, stream)
        assert digest(partial) == expected, name
        partial.replace(destination)
        print('Verified retained file', name, size, flush=True)
    with tarfile.open(folder / 'raw.tar.gz') as stream:
        members = stream.getmembers()
        assert all(m.isfile() and m.name == 'raw/' + Path(m.name).name for m in members)
        assert len({m.name for m in members}) == len(members)
        for member in members:
            with (folder / Path(member.name).name).open('wb') as destination:
                source = stream.extractfile(member)
                while data := source.read(1024 * 1024):
                    destination.write(data)
    worker['raw_archive_sha256'] = result['raw.tar.gz_sha256']
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    collection = {'collector_sha256': digest(Path(__file__)), 'archive_sha256': worker['raw_archive_sha256'],
        'archive_members': len(members), 'native_actions_executed_by_collector': 0}
    (root / 'collection.json').write_text(json.dumps(collection, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(collection), flush=True)


if __name__ == '__main__':
    main(Path(sys.argv[1]))
