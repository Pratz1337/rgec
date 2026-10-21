"""Run genuine V26 compiler stream/failure observations with durable evidence."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

import modal


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main(root, build_native=False):
    prior_root = Path('runs/rgec-modal-native-report-admission-2026-10-07-v26-v2')
    prior_bytes = (prior_root / 'evidence.json').read_bytes()
    prior = json.loads(prior_bytes); worker, = prior['sandboxes']
    assert worker['returncode'] == worker['cleanup_returncode'] == 0
    sources = [Path(__file__), Path('scripts/rgec_native_stream_probe.py'),
        Path('scripts/rgec_native_stream_trace.c'), Path('scripts/rgec_backend_probe.py'),
        Path('scripts/rgec_native_effect_probe.py'), Path('scripts/rgec_native_event_probe.py'),
        Path('src/unauthorized_channels/modal_recipient_entry.py'),
        Path('src/unauthorized_channels/clang_backend_continuation.cpp'),
        Path('src/unauthorized_channels/clang_residual_backend.h'),
        Path('src/unauthorized_channels/clang_backend_read_state.h')]
    if not build_native:
        for path, remote in zip(sources[-3:], ('/rgec-backend.cpp', '/clang_residual_backend.h', '/clang_backend_read_state.h')):
            assert sha(path.read_bytes()) == worker['tool_sha256'][remote]
    manifest = root / 'evidence.json'
    if not root.exists():
        root.mkdir(parents=True)
        for path in sources: (root / path.name).write_bytes(path.read_bytes())
        if build_native: (root/'native-build.py').write_bytes((prior_root/'native-build.py').read_bytes())
        (root / 'baseline-evidence.json').write_bytes(prior_bytes)
        config = {'prefix': root.name, 'tool_sha256': worker['tool_sha256']}
        (root / 'stream-config.json').write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8')
        evidence = {'platform': 'Modal', 'cpu': 2, 'memory_mib': 4096, 'gpu': None,
            'base_image_id': worker['image_id'], 'baseline_root': str(prior_root),
            'baseline_manifest_sha256': sha(prior_bytes), 'native_tool_sha256': worker['tool_sha256'],
            'source_sha256': {str(path): sha(path.read_bytes()) for path in sources},
            'config_sha256': sha((root / 'stream-config.json').read_bytes()),
            'runtime_network_blocked': True, 'durable_volume': 'rgec-native-report-evidence',
            'native_recompilations': 0, 'tracer_compiles': 1, 'sandbox': None,
            'build_native': build_native,
            'complete_closure_certified': False, 'adaptive_noninterference_proved': False,
            'production_shared_policy_enabled': False}
        manifest.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    evidence = json.loads(manifest.read_bytes())
    for name, expected in evidence['source_sha256'].items():
        assert sha((root / Path(name).name).read_bytes()) == expected
    def persist(): manifest.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    image = modal.Image.from_id(evidence['base_image_id'])
    for path in sources[1:7]: image = image.add_local_file(str(root / path.name), '/' + path.name, copy=True)
    image = image.add_local_file(str(root / 'stream-config.json'), '/stream-config.json', copy=True)
    volume = modal.Volume.from_name(evidence['durable_volume'])
    app = modal.App('rgec-v26-genuine-native-stream-failures')
    with modal.enable_output(), app.run(detach=True):
        if evidence.get('build_native') and 'built_image_id' not in evidence:
            for local,remote in ((root/'clang_backend_continuation.cpp','/rgec-backend.cpp'),
                (root/'clang_residual_backend.h','/clang_residual_backend.h'),
                (root/'clang_backend_read_state.h','/clang_backend_read_state.h'),
                (root/'native-build.py','/stream-native-build.py')):
                image=image.add_local_file(str(local),remote,copy=True)
            image=image.run_commands('/usr/bin/python3 -I /stream-native-build.py > /stream-native-build.stdout 2> /stream-native-build.stderr')
            fingerprint='import hashlib,json; paths='+repr(list(worker['tool_sha256']))+'; print(json.dumps({p:hashlib.sha256(open(p,"rb").read()).hexdigest() for p in paths}))'
            check=modal.Sandbox.create('/usr/bin/python3','-I','-c',fingerprint,app=app,image=image,cpu=1,memory=1024,timeout=180,block_network=True)
            check.wait(); out=check.stdout.read(); error=check.stderr.read()
            (root/'build-fingerprint.stdout').write_text(out,encoding='utf-8'); (root/'build-fingerprint.stderr').write_text(error,encoding='utf-8')
            evidence.update(build_fingerprint_sandbox_id=check.object_id,build_fingerprint_returncode=check.returncode); persist()
            assert check.returncode==0,error
            evidence.update(native_tool_sha256=json.loads(out),built_image_id=image.object_id,
                native_recompilations=1,build_script_sha256=sha((root/'native-build.py').read_bytes()))
            config=json.loads((root/'stream-config.json').read_bytes()); config['tool_sha256']=evidence['native_tool_sha256']
            (root/'stream-config.json').write_text(json.dumps(config,indent=2)+'\n',encoding='utf-8')
            evidence['config_sha256']=sha((root/'stream-config.json').read_bytes()); persist()
        if 'built_image_id' in evidence:
            image=modal.Image.from_id(evidence['built_image_id']).add_local_file(str(root/'stream-config.json'),'/stream-config.json',copy=True)
        if evidence['sandbox'] is None:
            sandbox = modal.Sandbox.create('/usr/bin/python3', '-I', '/rgec_native_stream_probe.py',
                app=app, image=image, cpu=2, memory=4096, timeout=1800,
                block_network=True, volumes={'/retained': volume})
            evidence['sandbox'] = {'id': sandbox.object_id, 'image_id': image.object_id,
                'termination_mode': 'native worker entrypoint exits'}; persist()
            print('Genuine native stream worker', sandbox.object_id, flush=True)
        else: sandbox = modal.Sandbox.from_id(evidence['sandbox']['id'])
        sandbox.wait(); evidence['sandbox']['cleanup_returncode'] = sandbox.returncode; persist()
        result_bytes = b''.join(volume.read_file(root.name + '/result.json'))
        (root / 'durable-result.json').write_bytes(result_bytes)
        result = json.loads(result_bytes)
        assert result['tool_sha256'] == evidence['native_tool_sha256']
        evidence['sandbox']['returncode'] = result['returncode']
        evidence['sandbox']['raw_archive_sha256'] = result['raw.tar.gz_sha256']; persist()
        for name in ('raw.tar.gz', 'stdout', 'stderr'):
            destination = root / name
            if destination.exists() and sha(destination.read_bytes()) == result[name + '_sha256']: continue
            partial = destination.with_name(destination.name + '.partial')
            with partial.open('w+b') as stream: volume.read_file_into_fileobj(root.name + '/' + name, stream)
            assert sha(partial.read_bytes()) == result[name + '_sha256']
            partial.replace(destination)
        folder = root / 'raw'; folder.mkdir(exist_ok=True)
        with tarfile.open(root / 'raw.tar.gz') as archive:
            members = archive.getmembers()
            assert len({m.name for m in members}) == len(members)
            for member in members:
                assert member.isfile() and member.name == 'raw/' + Path(member.name).name
                (folder / Path(member.name).name).write_bytes(archive.extractfile(member).read())
        assert evidence['sandbox']['returncode'] == evidence['sandbox']['cleanup_returncode'] == 0
        print('Collected genuine native stream/failure evidence; independent audit pending.', flush=True)


if __name__ == '__main__': main(Path(sys.argv[1]), '--build' in sys.argv[2:])
