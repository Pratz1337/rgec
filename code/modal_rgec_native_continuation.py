"""Test actual Clang output continuation on Modal, without a cache claim."""
import io
import json
import sys
import tarfile
from pathlib import Path
import modal
from modal_rgec_native import execute, read, sha, write

def main(root):
    root.mkdir(parents=True, exist_ok=False)
    paths = [Path(__file__), Path('src/unauthorized_channels/clang_output_continuation.cpp'),
             Path('scripts/rgec_native_continuation_probe.py'),
             Path('scripts/rgec_native_effect_probe.py'), Path('scripts/rgec_native_event_probe.py'),
             Path('modal_rgec_native.py'), Path('src/unauthorized_channels/modal_recipient_entry.py')]
    row = {'date': '2026-10-03', 'platform': 'Modal', 'gpu': None, 'cpu': 2,
           'memory_mib': 4096, 'network_blocked': True, 'shared_reuse_enabled': False,
           'admission_certified': False, 'source_sha256': {str(p): sha(p.read_bytes()) for p in paths}}
    for path in paths:
        (root / path.name).write_bytes(path.read_bytes())
    image = modal.Image.from_id('im-cWn7cCksmiECQIShla5S35').add_local_file(
        str(paths[1]), '/rgec-output-continuation.cpp', copy=True).run_commands(
        '/usr/local/bin/clang++ -std=c++14 -fPIC -shared -fno-rtti -I/usr/local/include '
        '/rgec-output-continuation.cpp -o /rgec-output-continuation.so')
    sandbox = None
    try:
        app = modal.App('rgec-native-continuation')
        with modal.enable_output(), app.run():
            sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app,
                image=image, cpu=2, memory=4096, timeout=600, block_network=True)
            row.update(sandbox_id=sandbox.object_id, image_id=image.object_id)
            print('Native continuation sandbox:', sandbox.object_id, flush=True)
            (root / 'evidence.json').write_text(json.dumps(row, indent=2), encoding='utf-8')
            for path in paths[2:5]:
                write(sandbox, '/' + path.name, path.read_bytes())
            code, out, error = execute(sandbox, '/usr/bin/python3', '-I',
                '/rgec_native_continuation_probe.py', timeout=480)
            row['returncode'] = code
            (root / 'probe.stdout').write_bytes(out)
            (root / 'probe.stderr').write_bytes(error)
            pack_code, _, pack_error = execute(sandbox, '/usr/bin/python3', '-I', '-c',
                "import tarfile; t=tarfile.open('/continuation-evidence.tar.gz','w:gz'); "
                "t.add('/workspace/native-continuation',arcname='raw'); t.close()")
            assert pack_code == 0, pack_error
            packed = read(sandbox, '/continuation-evidence.tar.gz')
            (root / 'raw.tar.gz').write_bytes(packed)
            row['raw_archive_sha256'] = sha(packed)
            with tarfile.open(fileobj=io.BytesIO(packed)) as archive:
                for member in archive:
                    if not member.isfile():
                        continue
                    parts = Path(member.name).parts
                    assert parts[0] == 'raw' and '..' not in parts
                    target = root.joinpath(*parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(archive.extractfile(member).read())
            assert code == 0, error[-2000:]
    except Exception as error:
        row['error'] = str(error)
        raise
    finally:
        if sandbox:
            sandbox.terminate()
            try:
                sandbox.wait()
            except modal.exception.SandboxTerminatedError:
                pass
            row['cleanup_returncode'] = sandbox.returncode
        (root / 'evidence.json').write_text(json.dumps(row, indent=2), encoding='utf-8')

if __name__ == '__main__':
    main(Path(sys.argv[1]))
