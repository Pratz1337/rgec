"""Build the native backend cutpoint and run genuine compiler cases on Modal."""
import json
import shlex
import sys
import tarfile
from pathlib import Path
import modal
from modal_rgec_native import execute, sha, write


def main(root, experiment=None):
    root.mkdir(parents=True, exist_ok=False)
    paths = [Path(__file__), Path('src/unauthorized_channels/clang_backend_continuation.cpp'),
             Path({'followup': 'scripts/rgec_backend_followup.py', 'followup-rebuilt': 'scripts/rgec_backend_followup.py', 'responses': 'scripts/rgec_backend_response_probe.py', 'responses-rebuilt': 'scripts/rgec_backend_response_probe.py'}.get(experiment, 'scripts/rgec_backend_probe.py')), Path('scripts/rgec_native_effect_probe.py'),
             Path('scripts/rgec_native_event_probe.py'),
             Path('src/unauthorized_channels/modal_recipient_entry.py'), Path('modal_rgec_native.py')]
    if experiment:
        paths.append(Path('scripts/rgec_backend_probe.py'))
    row = {'date': '2026-10-03', 'platform': 'Modal', 'cpu': 2, 'memory_mib': 4096,
           'gpu': None, 'runtime_network_blocked': True, 'complete_closure_certified': False,
           'production_shared_policy_enabled': False,
           'source_sha256': {str(path): sha(path.read_bytes()) for path in paths}}
    for path in paths:
        (root / path.name).write_bytes(path.read_bytes())
    build = """import glob,os,subprocess
symbols=subprocess.check_output(['/usr/bin/nm','-D','/usr/local/bin/clang']).decode()
symbol=next(line.split()[-1] for line in symbols.splitlines() if 'EmitBackendOutput' in line)
llvm=subprocess.check_output(['/usr/local/bin/llvm-config','--libs','--system-libs']).decode().split()
command=['/usr/local/bin/clang++','-std=c++14','-fno-rtti','-I/usr/local/include',
 '-DRGEC_BACKEND_SYMBOL="'+symbol+'"','/rgec-backend.cpp','-o','/rgec-backend',
 '-Wl,--wrap='+symbol,'-Wl,--start-group']+glob.glob('/usr/local/lib/libclang*.a')+['-L/usr/local/lib']+llvm+['-Wl,--end-group']
print('Native backend symbol: '+symbol,flush=True)
subprocess.check_call(command)
os.mkdir('/rgec-driver')
os.symlink('/rgec-backend','/rgec-driver/clang-7')
"""
    if experiment and experiment not in ('responses-rebuilt', 'followup-rebuilt'):
        assert sha(paths[1].read_bytes()) == '74a3f00423e6dee20bad2ab336d61e96c48cb8c9eebd21b72e557f9dd8f2d65b', \
            'Pinned October 3 source changed; use followup-rebuilt or responses-rebuilt.'
        image = modal.Image.from_id('im-YLBw1X843p0Qaw0NIbkR39')
    else:
        image = modal.Image.from_id('im-cWn7cCksmiECQIShla5S35').add_local_file(
            str(paths[1]), '/rgec-backend.cpp', copy=True).run_commands(
                '/usr/bin/python3 -I -c ' + shlex.quote('exec(' + repr(build) + ')'))
    sandbox = None
    try:
        app = modal.App('rgec-native-backend-continuation')
        with modal.enable_output(), app.run():
            sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app,
                image=image, cpu=2, memory=4096, timeout=900, block_network=True)
            row.update(sandbox_id=sandbox.object_id, image_id=image.object_id)
            print('Native backend sandbox: ' + sandbox.object_id, flush=True)
            (root / 'evidence.json').write_text(json.dumps(row, indent=2), encoding='utf-8')
            for path in paths[2:5]:
                write(sandbox, '/' + path.name, path.read_bytes())
            if experiment:
                write(sandbox, '/rgec_backend_probe.py', paths[-1].read_bytes())
            code, out, error = execute(sandbox, '/usr/bin/python3', '-I',
                '/' + paths[2].name, timeout=780)
            row['returncode'] = code
            (root / 'probe.stdout').write_bytes(out)
            (root / 'probe.stderr').write_bytes(error)
            pack_code, _, pack_error = execute(sandbox, '/usr/bin/python3', '-I', '-c',
                "import glob,os,tarfile; t=tarfile.open('/backend-evidence.tar.gz','w:gz'); "
                "[t.add(p,arcname='raw/'+os.path.basename(p)) for p in "
                "glob.glob('/workspace/backend-continuation/*') if os.path.isfile(p)]; t.close()")
            assert pack_code == 0, pack_error
            hash_code, identity, hash_error = execute(sandbox, '/usr/bin/sha256sum', '/backend-evidence.tar.gz')
            assert hash_code == 0, hash_error
            sandbox.filesystem.copy_to_local('/backend-evidence.tar.gz', root / 'raw.tar.gz')
            row['raw_archive_sha256'] = sha((root / 'raw.tar.gz').read_bytes())
            assert row['raw_archive_sha256'] == identity.decode().split()[0]
            with tarfile.open(root / 'raw.tar.gz') as archive:
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
    assert len(sys.argv) == 2 or sys.argv[2] in ('followup', 'followup-rebuilt', 'responses', 'responses-rebuilt')
    main(Path(sys.argv[1]), sys.argv[2] if len(sys.argv) > 2 else None)
