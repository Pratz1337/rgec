"""Build and test captured native backend state on Modal, never on the laptop."""
import json
import shlex
import shutil
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import modal
from modal_rgec_native import execute, read, sha, write


def collect(sandbox, root, phase, remote_root='/workspace/backend-continuation'):
    archive_path = remote_root + '/raw.tar.gz' if remote_root != '/workspace/backend-continuation' else '/residual-raw.tar.gz'
    code, _, error = execute(sandbox, '/usr/bin/python3', '-I', '-c',
        "import glob,os,sys,tarfile; t=tarfile.open(sys.argv[2],'w:gz'); "
        "[t.add(p,arcname='raw/'+os.path.basename(p)) for p in "
        "glob.glob(sys.argv[1]+'/*') if os.path.isfile(p) and p!=sys.argv[2]]; t.close()", remote_root, archive_path)
    assert code == 0, error
    code, identity, error = execute(sandbox, '/usr/bin/sha256sum', archive_path)
    assert code == 0, error
    target = root / phase
    target.mkdir()
    try:
        sandbox.filesystem.copy_to_local(archive_path, target / 'raw.tar.gz')
    except modal.exception.NotFoundError:
        if sandbox.poll() is not None:
            raise
        # A live command namespace can outlast an unavailable filesystem API.
        # The existing finite-read helper checks original byte length and hash.
        (target / 'raw.tar.gz').write_bytes(read(sandbox, archive_path))
    digest = sha((target / 'raw.tar.gz').read_bytes())
    assert digest == identity.decode().split()[0]
    with tarfile.open(target / 'raw.tar.gz') as archive:
        for member in archive:
            assert member.isfile() and member.name.startswith('raw/')
            assert Path(member.name).name == member.name[4:]
            (target / Path(member.name).name).write_bytes(archive.extractfile(member).read())
    return digest


def main(root, capture_root=None, experiment=None):
    root.mkdir(parents=True, exist_ok=False)
    paths = [Path(__file__), Path('src/unauthorized_channels/clang_backend_continuation.cpp'),
        Path('src/unauthorized_channels/clang_residual_backend.h'),
        Path('scripts/rgec_residual_probe.py'), Path('scripts/rgec_backend_probe.py'),
        Path('scripts/rgec_native_effect_probe.py'), Path('scripts/rgec_native_event_probe.py'),
        Path('src/unauthorized_channels/modal_recipient_entry.py'), Path('modal_rgec_native.py'),
        Path('src/unauthorized_channels/clang_backend_read_state.h')]
    if experiment:
        paths.append(Path('scripts/rgec_' + {'callback-responses': 'callback_response',
                                           'parametric': 'parametric',
                                           'backend-read': 'backend_read'}[experiment] + '_probe.py'))
    row = {'date': datetime.now(timezone.utc).date().isoformat(), 'platform': 'Modal', 'cpu': 2, 'memory_mib': 4096,
        'gpu': None, 'production_shared_policy_enabled': False,
        'complete_closure_certified': False, 'sandboxes': [],
        'source_sha256': {str(path): sha(path.read_bytes()) for path in paths}}
    for path in paths:
        (root / path.name).write_bytes(path.read_bytes())
    build = """import glob,os,subprocess
symbols=subprocess.check_output(['/usr/bin/nm','-D','/usr/local/bin/clang']).decode()
symbol=next(line.split()[-1] for line in symbols.splitlines() if 'EmitBackendOutput' in line)
llvm=subprocess.check_output(['/usr/local/bin/llvm-config','--libs','--system-libs']).decode().split()
wrapped={
 'MAP_PARSE':'_ZN4llvm14SymbolRewriter16RewriteMapParser5parseERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPNS2_4listISt10unique_ptrINS0_17RewriteDescriptorESt14default_deleteISC_EESaISF_EEE',
 'READ_FILE':'_ZN4llvm12MemoryBuffer7getFileERKNS_5TwineElbb',
 'FP_INIT':'_ZN4llvm6legacy19FunctionPassManager16doInitializationEv',
 'FP_RUN':'_ZN4llvm6legacy19FunctionPassManager3runERNS_8FunctionE',
 'FP_END':'_ZN4llvm6legacy19FunctionPassManager14doFinalizationEv',
 'PM_RUN':'_ZN4llvm6legacy11PassManager3runERNS_6ModuleE'}
native_symbols=subprocess.check_output(['/usr/bin/nm','--defined-only',
 '/usr/local/lib/libLLVMTransformUtils.a','/usr/local/lib/libLLVMCore.a','/usr/local/lib/libLLVMSupport.a']).decode()
assert all(any(line.split()[-1:]==[value] for line in native_symbols.splitlines()) for value in wrapped.values())
command=['/usr/local/bin/clang++','-std=c++14','-fno-rtti','-I/usr/local/include','-I/',
 '-DRGEC_RESIDUAL_BUILD','-DRGEC_READ_BUILD','-DRGEC_BACKEND_SYMBOL="'+symbol+'"']
command+=['-DRGEC_'+name+'_SYMBOL="'+value+'"' for name,value in wrapped.items()]
command+=['/rgec-backend.cpp','-o','/rgec-backend','-Wl,--wrap='+symbol]
command+=['-Wl,--wrap='+value for value in wrapped.values()]
command+=['-Wl,--start-group']+glob.glob('/usr/local/lib/libclang*.a')+['-L/usr/local/lib']+llvm+['-Wl,--end-group']
subprocess.check_call(command)
os.mkdir('/rgec-driver'); os.symlink('/rgec-backend','/rgec-driver/clang-7')
"""
    if capture_root:
        previous = json.loads((capture_root / 'evidence.json').read_text(encoding='utf-8'))
        capture = next(item for item in previous['sandboxes'] if item['phase'] == 'capture')
        assert capture['returncode'] == 0
        assert sha((capture_root / paths[1].name).read_bytes()) == sha(paths[1].read_bytes())
        assert sha((capture_root / paths[3].name).read_bytes()) == sha(paths[3].read_bytes()), 'capture format changed'
        assert sha((capture_root / paths[9].name).read_bytes()) == sha(paths[9].read_bytes()), 'native read boundary changed'
        assert sha((capture_root / 'capture/raw.tar.gz').read_bytes()) == capture['raw_archive_sha256']
        shutil.copytree(capture_root / 'capture', root / 'capture')
        row['imported_capture'] = {'root': str(capture_root), 'sandbox': capture}
        image = modal.Image.from_id(capture['image_id'])
        if sha((capture_root / paths[2].name).read_bytes()) != sha(paths[2].read_bytes()):
            row['producer_header_changed_from_capture'] = True
            # The capture reader format must match; a new producer records its
            # actual identity rather than silently reuse the old compiler.
            image = modal.Image.from_id('im-cWn7cCksmiECQIShla5S35').add_local_file(
                str(root / paths[1].name), '/rgec-backend.cpp', copy=True).add_local_file(
                str(root / paths[2].name), '/clang_residual_backend.h', copy=True).add_local_file(
                str(root / paths[9].name), '/clang_backend_read_state.h', copy=True).run_commands(
                    '/usr/bin/python3 -I -c ' + shlex.quote('exec(' + repr(build) + ')'))
    else:
        image = modal.Image.from_id('im-cWn7cCksmiECQIShla5S35').add_local_file(
            str(root / paths[1].name), '/rgec-backend.cpp', copy=True).add_local_file(
            str(root / paths[2].name), '/clang_residual_backend.h', copy=True).add_local_file(
            str(root / paths[9].name), '/clang_backend_read_state.h', copy=True).run_commands(
                '/usr/bin/python3 -I -c ' + shlex.quote('exec(' + repr(build) + ')'))
    app = modal.App('rgec-native-residual-state')
    live = []
    try:
        with modal.enable_output(), app.run():
            for phase in (('producer', 'replay') if capture_root else ('capture', 'producer', 'replay')):
                sandbox = modal.Sandbox.create('/bin/sleep', 'infinity', app=app,
                    image=image, cpu=2, memory=4096, timeout=1200, block_network=True)
                live.append(sandbox)
                entry = {'phase': phase, 'id': sandbox.object_id, 'image_id': image.object_id}
                row['sandboxes'].append(entry)
                print(phase + ' sandbox: ' + sandbox.object_id, flush=True)
                for path in paths[3:8]:
                    write(sandbox, '/' + path.name, (root / path.name).read_bytes())
                if experiment:
                    write(sandbox, '/' + paths[-1].name, (root / paths[-1].name).read_bytes())
                if phase != 'capture':
                    for prior_phase in ('capture',) if phase == 'producer' else ('capture', 'producer'):
                        remote = '/transfer-' + prior_phase + '.tar.gz'
                        try:
                            sandbox.filesystem.copy_from_local(root / prior_phase / 'raw.tar.gz', remote)
                        except modal.exception.NotFoundError:
                            if sandbox.poll() is not None:
                                raise
                            write(sandbox, remote, (root / prior_phase / 'raw.tar.gz').read_bytes())
                        code, digest, error = execute(sandbox, '/usr/bin/sha256sum', remote)
                        assert code == 0 and digest.decode().split()[0] == sha(
                            (root / prior_phase / 'raw.tar.gz').read_bytes()), error
                        code, _, error = execute(sandbox, '/usr/bin/python3', '-I', '-c',
                            "import os,sys,tarfile; target=sys.argv[2]; os.mkdir(target); "
                            "archive=tarfile.open(sys.argv[1]); "
                            "members=archive.getmembers(); "
                            "assert all(m.isfile() and m.name.startswith('raw/') and "
                            "os.path.basename(m.name)==m.name[4:] for m in members); "
                            "[open(target+'/'+os.path.basename(m.name),'wb').write(archive.extractfile(m).read()) "
                            "for m in members]", remote, '/transfer-' + prior_phase)
                        assert code == 0, error
                code, out, error = execute(sandbox, '/usr/bin/python3', '-I',
                    '/' + paths[-1].name if experiment
                    else '/rgec_residual_probe.py', phase, timeout=1000)
                entry['returncode'] = code
                (root / (phase + '.stdout')).write_bytes(out)
                (root / (phase + '.stderr')).write_bytes(error)
                entry['raw_archive_sha256'] = collect(sandbox, root, phase)
                (root / 'evidence.json').write_text(json.dumps(row, indent=2), encoding='utf-8')
                assert code == 0, error[-3000:]
                sandbox.terminate()
                try:
                    sandbox.wait()
                except modal.exception.SandboxTerminatedError:
                    pass
                entry['cleanup_returncode'] = sandbox.returncode
                live.remove(sandbox)
    except Exception as error:
        row['error'] = str(error)
        raise
    finally:
        for sandbox in live:
            sandbox.terminate()
            try:
                sandbox.wait()
            except modal.exception.SandboxTerminatedError:
                pass
            next(item for item in row['sandboxes'] if item['id'] == sandbox.object_id)['cleanup_returncode'] = sandbox.returncode
        (root / 'evidence.json').write_text(json.dumps(row, indent=2), encoding='utf-8')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[2] in ('callback-responses', 'parametric', 'backend-read'):
        main(Path(sys.argv[1]), experiment=sys.argv[2])
    else:
        main(Path(sys.argv[1]), Path(sys.argv[2]) if len(sys.argv) == 3 else None)
