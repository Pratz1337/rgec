"""Run the real clock/metadata/dependency audit on Modal CPUs."""

import io
import json
import sys
import tarfile
from pathlib import Path

import modal

from modal_rgec_native import execute, read, sha, write


def main(root, reference):
    root.mkdir(parents=True, exist_ok=False)
    record = json.loads(reference.read_text())
    assert record['full_native_build_completed'] and record['native_child_returncode'] == 0
    evidence = {'platform': 'Modal', 'reference_snapshot_id': record['configured_snapshot_id'],
                'cpu': 2, 'memory_mib': 4096, 'gpu': None, 'network_blocked': True,
                'shared_reuse_enabled': False, 'complete_closure_certified': False}
    sandbox = None
    image = modal.Image.from_id(record['configured_snapshot_id']).add_local_file(
        'src/unauthorized_channels/clang_closure_plugin.cpp', '/rgec-closure.cpp', copy=True
    ).run_commands('/usr/local/bin/clang++ -std=c++14 -fPIC -shared -fno-rtti '
                   '-I/usr/local/include /rgec-closure.cpp -o /rgec-closure.so')
    try:
        app = modal.App('rgec-native-closure')
        with modal.enable_output(), app.run():
            sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app,
                image=image,
                cpu=2, memory=4096, timeout=600, block_network=True)
            evidence['sandbox_id'] = sandbox.object_id
            evidence['plugin_image_id'] = image.object_id
            print('Modal closure audit:', sandbox.object_id, flush=True)
            for path in (Path(__file__), Path('scripts/rgec_closure_probe.py'),
                         Path('scripts/rgec_native_effect_probe.py'),
                         Path('src/unauthorized_channels/clang_closure_plugin.cpp')):
                data = path.read_bytes()
                (root / path.name).write_bytes(data)
                write(sandbox, '/' + path.name, data)
            plugin_binary = read(sandbox, '/rgec-closure.so')
            (root / 'rgec-closure.so').write_bytes(plugin_binary)
            evidence['plugin_binary_sha256'] = sha(plugin_binary)
            code, out, error = execute(sandbox, '/usr/bin/python3', '/rgec_closure_probe.py', timeout=480)
            evidence['returncode'] = code
            (root / 'probe.stdout').write_bytes(out)
            (root / 'probe.stderr').write_bytes(error)
            pack = "import glob,os,tarfile; t=tarfile.open('/closure-evidence.tar.gz','w:gz'); " \
                   "[t.add(p,arcname=os.path.basename(p)) for p in glob.glob('/workspace/closure/*') if os.path.isfile(p)]; t.close()"
            pack_code, _, pack_error = execute(sandbox, '/usr/bin/python3', '-c', pack)
            assert pack_code == 0, pack_error
            packed = read(sandbox, '/closure-evidence.tar.gz')
            (root / 'raw.tar.gz').write_bytes(packed)
            evidence['raw_archive_sha256'] = sha(packed)
            with tarfile.open(fileobj=io.BytesIO(packed)) as archive:
                for member in archive:
                    assert member.isfile() and Path(member.name).name == member.name
                    name = 'native-closure.json' if member.name == 'evidence.json' else member.name
                    (root / name).write_bytes(archive.extractfile(member).read())
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
