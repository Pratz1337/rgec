"""Cloud-only extraction of a pinned native matcher and its real table."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import modal


DOWNLOAD = r'''
import hashlib,json,os,urllib.request
c=json.load(open('/region-capsule-config.json')); os.mkdir('/upstream'); rows=[]
for path in c['source_files']:
 url='https://raw.githubusercontent.com/llvm/llvm-project/'+c['upstream_revision']+'/'+path
 data=urllib.request.urlopen(url,timeout=120).read()
 with open('/upstream/'+path.replace('/','__'),'wb') as f: f.write(data)
 rows.append(dict(url=url,sha256=hashlib.sha256(data).hexdigest()))
with open('/upstream/downloads.json','w') as f: json.dump(rows,f,indent=2)
'''


def sha(data): return hashlib.sha256(data).hexdigest()


def main(root):
    prior_root = Path('runs/rgec-modal-native-segment-samples-2026-10-10-v2')
    prior = json.loads((prior_root / 'evidence.json').read_bytes())
    assert prior['sandbox']['returncode'] == prior['sandbox']['cleanup_returncode'] == 0
    paths = [Path(__file__), Path('scripts/rgec_native_region_capsule.py')]
    manifest = root / 'evidence.json'
    if not root.exists():
        root.mkdir(parents=True)
        for path in paths: (root / path.name).write_bytes(path.read_bytes())
        config = dict(prefix=root.name, native_sha256=json.loads((prior_root / 'segment-profile-config.json').read_bytes())['native_sha256'],
            upstream_revision='4021cee996f75e8f591991e53180d1d29dfd20d6', source_files=[
                'llvm/lib/CodeGen/SelectionDAG/SelectionDAGISel.cpp',
                'llvm/lib/CodeGen/SelectionDAG/SelectionDAG.cpp',
                'llvm/include/llvm/CodeGen/SelectionDAGISel.h',
                'llvm/include/llvm/CodeGen/SelectionDAGNodes.h',
                'llvm/include/llvm/CodeGen/SelectionDAG.h'])
        (root / 'region-capsule-config.json').write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8')
        (root / 'download-upstream.py').write_text(DOWNLOAD, encoding='utf-8')
        m = dict(platform='Modal', cpu=2, memory_mib=6144, gpu=None,
            prepared_native_image_id=prior['sandbox']['image_id'], durable_volume=prior['durable_volume'],
            profile_manifest_sha256=sha((prior_root / 'evidence.json').read_bytes()),
            sources={p.name: sha((root / p.name).read_bytes()) for p in paths},
            config_sha256=sha((root / 'region-capsule-config.json').read_bytes()),
            download_script_sha256=sha((root / 'download-upstream.py').read_bytes()),
            sandbox=None, compiler_actions=0, runtime_network_blocked=True,
            complete_closure_certified=False, substantial_novelty_established=False)
        manifest.write_text(json.dumps(m, indent=2) + '\n', encoding='utf-8')
    m = json.loads(manifest.read_bytes())
    for name, expected in m['sources'].items(): assert sha((root / name).read_bytes()) == expected
    assert sha((root / 'region-capsule-config.json').read_bytes()) == m['config_sha256']
    assert sha((root / 'download-upstream.py').read_bytes()) == m['download_script_sha256']
    def persist(): manifest.write_text(json.dumps(m, indent=2) + '\n', encoding='utf-8')
    volume = modal.Volume.from_name(m['durable_volume']); app = modal.App('rgec-original-native-region-capsule')
    with modal.enable_output(), app.run(detach=True):
        if m['sandbox'] is None:
            image = modal.Image.from_id(m['prepared_native_image_id'])
            for name in ('rgec_native_region_capsule.py', 'region-capsule-config.json', 'download-upstream.py'):
                image = image.add_local_file(str(root / name), '/' + name, copy=True)
            image = image.run_commands('/usr/bin/python3 -I /download-upstream.py')
            sandbox = modal.Sandbox.create('/usr/bin/python3', '-I', '/rgec_native_region_capsule.py',
                app=app, image=image, cpu=2, memory=6144, timeout=600, block_network=True, volumes={'/retained': volume})
            m['sandbox'] = dict(id=sandbox.object_id, image_id=image.object_id); persist()
            print('Native region capsule', sandbox.object_id, flush=True)
        else: sandbox = modal.Sandbox.from_id(m['sandbox']['id'])
        sandbox.wait(); m['sandbox']['cleanup_returncode'] = sandbox.returncode; persist()
        data = b''.join(volume.read_file(root.name + '/result.json')); (root / 'durable-result.json').write_bytes(data)
        result = json.loads(data); m['sandbox']['returncode'] = result['returncode']; persist()
        for name in ('raw.tar.gz', 'stdout', 'stderr'):
            data = b''.join(volume.read_file(root.name + '/' + name)); assert sha(data) == result[name + '_sha256']
            (root / name).write_bytes(data)
        m['sandbox']['raw_archive_sha256'] = result['raw.tar.gz_sha256']; persist()
        (root / 'raw').mkdir(exist_ok=True)
        with tarfile.open(root / 'raw.tar.gz') as archive:
            members = archive.getmembers(); assert len({v.name for v in members}) == len(members)
            for member in members:
                assert member.isfile() and member.name == 'raw/' + Path(member.name).name
                (root / member.name).write_bytes(archive.extractfile(member).read())
        print('Collected capsule', result['returncode'], sandbox.returncode, flush=True)
        assert result['returncode'] == sandbox.returncode == 0


if __name__ == '__main__': main(Path(sys.argv[1]))
