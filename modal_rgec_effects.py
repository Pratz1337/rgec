"""Orchestrate real native filesystem-effect experiments on Modal CPUs."""

import io
import json
import shlex
import sys
import tarfile
from pathlib import Path

import modal

from modal_rgec_native import execute, read, sha, write


def main(root, reference):
    root.mkdir(parents=True, exist_ok=False)
    record = json.loads(reference.read_text())
    assert record['full_native_build_completed'] and record['native_child_returncode'] == 0
    app = modal.App('rgec-recipient-effects')
    archive_url = 'https://github.com/ccache/ccache/releases/download/v4.14.1/ccache-4.14.1-linux-x86_64-musl-static.tar.gz'
    download = 'import urllib.request; ' + \
               'urllib.request.urlretrieve(' + repr(archive_url) + ',"/opt/ccache/release.tar.gz"); ' + \
               'urllib.request.urlretrieve(' + repr(archive_url + '.minisig') + ',"/opt/ccache/release.minisig")'
    image = modal.Image.from_id(record['configured_snapshot_id']).run_commands(
        'mkdir -p /opt/ccache && /usr/bin/python3 -c ' + shlex.quote(download) + ' '
        '&& tar -xzf /opt/ccache/release.tar.gz --strip-components=1 -C /opt/ccache '
        '&& /opt/ccache/ccache --version')
    evidence = {'platform': 'Modal', 'reference_record_sha256': sha(reference.read_bytes()),
                'reference_snapshot_id': record['configured_snapshot_id'],
                'cpu': 2, 'memory_mib': 4096, 'gpu': None, 'network_blocked': True,
                'shared_reuse_enabled': False}
    sandbox = None
    try:
        with modal.enable_output(), app.run():
            sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app,
                      image=image,
                      cpu=2, memory=4096, timeout=900, block_network=True)
            evidence['sandbox_id'] = sandbox.object_id
            evidence['ccache_image_id'] = image.object_id
            evidence['ccache_archive_url'] = archive_url
            probe = Path('scripts/rgec_native_effect_probe.py').read_bytes()
            (root / 'rgec_native_effect_probe.py').write_bytes(probe)
            (root / Path(__file__).name).write_bytes(Path(__file__).read_bytes())
            write(sandbox, '/rgec-native-effect-probe.py', probe)
            recipient = Path('src/unauthorized_channels/recipient_effect.py').read_bytes()
            (root / 'recipient_effect.py').write_bytes(recipient)
            write(sandbox, '/recipient_effect.py', recipient)
            print('Modal native effect probe:', sandbox.object_id, flush=True)
            code, output, error = execute(sandbox, '/usr/bin/python3', '/rgec-native-effect-probe.py', timeout=750)
            (root / 'probe.stdout').write_bytes(output)
            (root / 'probe.stderr').write_bytes(error)
            evidence['returncode'] = code
            # Preserve partial measurements on failure, too.
            try:
                data = read(sandbox, '/workspace/native-effects/evidence.json')
                (root / 'native-effects.json').write_bytes(data)
                native = json.loads(data)
                evidence['measured_actions'] = len(native['actions'])
                pack = "import glob,os,tarfile; paths=glob.glob('/workspace/native-effects/*.stdout')+" \
                       "glob.glob('/workspace/native-effects/*.stderr')+glob.glob('/workspace/native-effects/*.ccache-log')+" \
                       "glob.glob('/workspace/native-effects/*.payload.o')+['/opt/ccache/release.tar.gz','/opt/ccache/release.minisig']; " \
                       "t=tarfile.open('/evidence.tar.gz','w:gz'); " \
                       "[t.add(p,arcname=os.path.basename(p)) for p in paths]; t.close()"
                pack_code, _, pack_error = execute(sandbox, '/usr/bin/python3', '-c', pack)
                assert pack_code == 0, pack_error
                packed = read(sandbox, '/evidence.tar.gz')
                evidence['raw_archive_sha256'] = sha(packed)
                (root / 'raw.tar.gz').write_bytes(packed)
                with tarfile.open(fileobj=io.BytesIO(packed)) as archive:
                    for member in archive:
                        assert member.isfile() and Path(member.name).name == member.name
                        (root / member.name).write_bytes(archive.extractfile(member).read())
            except Exception as collector_error:
                evidence['collector_error'] = str(collector_error)
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
                pass  # Intentional termination of the idle sandbox supervisor.
            evidence['cleanup_returncode'] = sandbox.returncode
        (root / 'evidence.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]))
