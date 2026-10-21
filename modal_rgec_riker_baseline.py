"""Build pinned Riker on Modal and compare actual compiler recipient effects."""
import json
import concurrent.futures
import hashlib
import io
import sys
import tarfile
import urllib.request
from pathlib import Path

import modal

from modal_rgec_native import execute, sha, write
from modal_rgec_residual import collect


COMMIT = 'bae684b455a4d8fa010fc04b471f5ca9b408f6a8'
ARCHIVES = {
    'riker': ('https://codeberg.org/curtsinger/riker/archive/' + COMMIT + '.tar.gz', '/opt/riker'),
    'BLAKE3': ('https://codeload.github.com/BLAKE3-team/BLAKE3/tar.gz/49a04ca23d10662cc7e5a38fb40f0955224852b5', '/opt/riker/deps/BLAKE3'),
    'CLI11': ('https://codeload.github.com/CLIUtils/CLI11/tar.gz/c57000e582fae45b01cd8074c79c81897379cbe5', '/opt/riker/deps/CLI11'),
    'fmt': ('https://codeload.github.com/fmtlib/fmt/tar.gz/c4ee726532178e556d923372f29163bd206d7732', '/opt/riker/deps/fmt'),
}


def main(root, source_prior=None):
    root.mkdir(parents=True, exist_ok=False)
    prior = Path('runs/rgec-modal-native-cas-cold-hit-2026-10-04')
    manifest = json.loads((prior / 'evidence.json').read_text(encoding='utf-8'))
    baseline = manifest['toolchain']
    paths = [Path(__file__), Path('modal_rgec_native.py'), Path('modal_rgec_residual.py'),
        Path('scripts/rgec_native_riker_probe.py'), Path('scripts/rgec_backend_probe.py'),
        Path('scripts/rgec_native_effect_probe.py'), Path('scripts/rgec_native_event_probe.py'),
        Path('src/unauthorized_channels/modal_recipient_entry.py')]
    result = {'platform': 'Modal', 'gpu': None, 'riker_commit': COMMIT,
        'riker_repository': 'https://codeberg.org/curtsinger/riker', 'sandboxes': [],
        'source_sha256': {}, 'captured_project_inputs': manifest['captured_project_inputs'],
        'project_archive_sha256': sha((prior / 'project-inputs.tar.gz').read_bytes()),
        'original_capture_keys': manifest['original_capture_keys'], 'native_toolchain': baseline}
    for path in paths:
        data = path.read_bytes(); (root / path.name).write_bytes(data)
        result['source_sha256'][str(path)] = sha(data)
    (root / 'project-inputs.tar.gz').write_bytes((prior / 'project-inputs.tar.gz').read_bytes())
    try:
        tree_url = 'https://codeberg.org/api/v1/repos/curtsinger/riker/git/trees/' + COMMIT + '?recursive=true'
        cached = json.loads((source_prior / 'evidence.json').read_text(encoding='utf-8')) if source_prior else None
        if cached:
            assert cached['riker_commit'] == COMMIT
            result['source_preparation_record'] = str(source_prior)
            result['source_preparation_record_sha256'] = sha((source_prior / 'evidence.json').read_bytes())
        tree = (source_prior / 'official-source-tree.json').read_bytes() if cached else urllib.request.urlopen(tree_url, timeout=30).read()
        (root / 'official-source-tree.json').write_bytes(tree)
        links = {x['path']: x['sha'] for x in json.loads(tree)['tree'] if x['mode'] == '160000'}
        image = modal.Image.from_id(baseline['image_id']).apt_install('make')
        result['source_archives'] = {}
        for name, (url, destination) in ARCHIVES.items():
            if name != 'riker': assert links['deps/' + name] in url
            if cached:
                data = (source_prior / (name + '-source.tar.gz')).read_bytes()
                assert sha(data) == cached['source_archives'][name]['sha256']
                if name == 'riker': result['riker_build_source_blob_ids'] = cached['riker_build_source_blob_ids']
            elif name == 'riker':
                files = [entry for entry in json.loads(tree)['tree'] if entry['type'] == 'blob' and
                    (entry['path'].startswith('src/') or entry['path'] in ('Makefile', '.gitmodules', 'LICENSE.md'))]
                def fetch(entry):
                    source_url = 'https://codeberg.org/curtsinger/riker/raw/commit/' + COMMIT + '/' + entry['path']
                    contents = urllib.request.urlopen(source_url, timeout=30).read()
                    assert len(contents) == entry['size']
                    assert hashlib.sha1(b'blob ' + str(len(contents)).encode() + b'\0' + contents).hexdigest() == entry['sha']
                    return entry, contents
                buffer = io.BytesIO()
                with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool, tarfile.open(fileobj=buffer, mode='w:gz') as archive:
                    for entry, contents in pool.map(fetch, files):
                        info = tarfile.TarInfo('riker/' + entry['path']); info.size = len(contents)
                        info.mode = int(entry['mode'], 8) & 0o777; archive.addfile(info, io.BytesIO(contents))
                data = buffer.getvalue()
                result['riker_build_source_blob_ids'] = {entry['path']: entry['sha'] for entry in files}
            else: data = urllib.request.urlopen(url, timeout=30).read()
            archive = root / (name + '-source.tar.gz'); archive.write_bytes(data)
            result['source_archives'][name] = {'url': url, 'sha256': sha(data), 'bytes': len(data)}
            image = image.add_local_file(str(archive), '/' + archive.name, copy=True).run_commands(
                'mkdir -p ' + destination + ' && tar --strip-components=1 -xzf /' + archive.name + ' -C ' + destination)
        image = image.run_commands('cd /opt/riker && make -j4 debug > /riker-build.log 2>&1 || { cat /riker-build.log; exit 1; }')
        with modal.enable_output(), modal.App('rgec-real-riker-baseline').run() as app:
            sb = modal.Sandbox.create('/bin/sleep', 'infinity', app=app, image=image,
                cpu=4, memory=8192, timeout=1800, block_network=True)
            row = {'phase': 'native-riker', 'id': sb.object_id, 'image_id': image.object_id}
            result['sandboxes'].append(row)
            try:
                code, out, error = execute(sb, '/usr/bin/sha256sum', baseline['compiler'],
                    '/opt/riker/debug/bin/rkr', '/opt/riker/debug/share/rkr/rkr-inject.so')
                assert code == 0, error
                row['tool_sha256'] = {line.split()[1]: line.split()[0] for line in out.decode().splitlines()}
                assert row['tool_sha256'][baseline['compiler']] == baseline['compiler_sha256']
                code, out, error = execute(sb, '/usr/bin/sha256sum',
                    *('/' + name + '-source.tar.gz' for name in ARCHIVES))
                assert code == 0 and {s.split()[1]: s.split()[0] for s in out.decode().splitlines()} == {
                    '/' + name + '-source.tar.gz': metadata['sha256'] for name, metadata in result['source_archives'].items()}, error
                sb.filesystem.copy_to_local('/riker-build.log', root / 'riker-build.log')
                write(sb, '/project-inputs.tar.gz', (root / 'project-inputs.tar.gz').read_bytes())
                code, _, error = execute(sb, '/usr/bin/python3', '-I', '-c',
                    "import tarfile;a=tarfile.open('/project-inputs.tar.gz');"
                    "assert all(m.isfile() and m.name.startswith('src/') and '..' not in m.name.split('/') for m in a.getmembers());a.extractall('/')")
                assert code == 0, error
                code, out, error = execute(sb, '/usr/bin/sha256sum', *result['captured_project_inputs'])
                assert code == 0 and {s.split()[1]: s.split()[0] for s in out.decode().splitlines()} == result['captured_project_inputs'], error
                for path in paths[3:]: write(sb, '/' + path.name, (root / path.name).read_bytes())
                code, out, error = execute(sb, '/usr/bin/python3', '-I', '/rgec_native_riker_probe.py', timeout=1200)
                row['returncode'] = code
                (root / 'native-riker.stdout').write_bytes(out); (root / 'native-riker.stderr').write_bytes(error)
                row['raw_archive_sha256'] = collect(sb, root, 'native-riker')
                assert code == 0, error[-3000:]
            finally:
                sb.terminate()
                try: sb.wait()
                except modal.exception.SandboxTerminatedError: pass
                row['cleanup_returncode'] = sb.returncode
    except Exception as error:
        result['error'] = str(error); raise
    finally:
        (root / 'evidence.json').write_text(json.dumps(result, indent=2), encoding='utf-8')


if __name__ == '__main__': main(Path(sys.argv[1]), Path(sys.argv[2]) if len(sys.argv) > 2 else None)
