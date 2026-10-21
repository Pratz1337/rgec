"""Run a pinned official staged-cache binary in the authentic Modal image."""
import io
import json
import shlex
import sys
import tarfile
from pathlib import Path
import modal
from modal_rgec_native import execute, read, sha, write

def main(root):
    root.mkdir(parents=True, exist_ok=False)
    release_path = Path('runs/rgec-zccache-release-2026-10-03.json')
    release = json.loads(release_path.read_text())
    asset = next(x for x in release['assets'] if x['name'] == 'zccache-v1.15.1-x86_64-unknown-linux-musl.tar.gz')
    assert release['tag_name'] == '1.15.1'
    assert asset['digest'] == 'sha256:cfbbb0f582f2ac8a237877052144033d3fbe6aa9b2ff823560d5f5432eb4bfa1'
    paths = [Path(__file__), Path('scripts/rgec_zccache_effect_probe.py'),
             Path('scripts/rgec_native_effect_probe.py'), Path('modal_rgec_native.py'),
             Path('src/unauthorized_channels/modal_recipient_entry.py'),
             Path('src/unauthorized_channels/clang_output_continuation.cpp'), release_path]
    row = {'date': '2026-10-03', 'platform': 'Modal', 'cpu': 2, 'memory_mib': 4096,
           'gpu': None, 'runtime_network_blocked': True, 'version': '1.15.1',
           'release_url': release['html_url'], 'asset': asset,
           'shared_policy_enabled': False, 'source_sha256': {str(p): sha(p.read_bytes()) for p in paths}}
    for path in paths:
        (root / path.name).write_bytes(path.read_bytes())
    download = """import hashlib,io,os,tarfile,urllib.request
os.makedirs('/opt/zccache',exist_ok=True)
data=urllib.request.urlopen(URL).read()
assert hashlib.sha256(data).hexdigest()==EXPECTED
open('/opt/zccache/release.tar.gz','wb').write(data)
t=tarfile.open(fileobj=io.BytesIO(data),mode='r:gz')
members=[m for m in t if m.isfile() and os.path.basename(m.name)=='zccache']
assert len(members)==1
open('/opt/zccache/zccache','wb').write(t.extractfile(members[0]).read())
os.chmod('/opt/zccache/zccache',0o755)
""".replace('URL', repr(asset['browser_download_url'])).replace('EXPECTED', repr(asset['digest'].split(':')[1]))
    image = modal.Image.from_id('im-2NQYihgzlRPX9RMs2LVyN6').run_commands(
        '/usr/bin/python3 -I -c ' + shlex.quote('exec(' + repr(download) + ')'))
    sandbox = None
    try:
        app = modal.App('rgec-staged-cache-baseline')
        with modal.enable_output(), app.run():
            sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app,
                image=image, cpu=2, memory=4096, timeout=900, block_network=True)
            row.update(sandbox_id=sandbox.object_id, image_id=image.object_id)
            print('Staged cache sandbox:', sandbox.object_id, flush=True)
            (root / 'evidence.json').write_text(json.dumps(row, indent=2), encoding='utf-8')
            for path in paths[1:3]:
                write(sandbox, '/' + path.name, path.read_bytes())
            code, hashes, error = execute(sandbox, '/usr/bin/sha256sum',
                '/opt/zccache/zccache', '/opt/zccache/release.tar.gz', '/rgec-output-continuation.so')
            assert code == 0, error
            (root / 'binary-identity.stdout').write_bytes(hashes)
            code, out, error = execute(sandbox, '/usr/bin/python3', '-I',
                '/rgec_zccache_effect_probe.py', timeout=780)
            row['returncode'] = code
            (root / 'probe.stdout').write_bytes(out)
            (root / 'probe.stderr').write_bytes(error)
            code_pack, _, error_pack = execute(sandbox, '/usr/bin/python3', '-I', '-c',
                "import glob,os,tarfile; t=tarfile.open('/zccache-evidence.tar.gz','w:gz'); "
                "[t.add(p,arcname='raw/'+os.path.basename(p)) for p in "
                "glob.glob('/workspace/zccache-effects/*') if os.path.isfile(p)]; t.close()")
            assert code_pack == 0, error_pack
            packed = read(sandbox, '/zccache-evidence.tar.gz')
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
