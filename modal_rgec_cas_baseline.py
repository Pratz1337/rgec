"""Run genuine released CAS comparisons on byte-pinned captured project sources."""
import io
import json
import posixpath
import struct
import sys
import tarfile
from pathlib import Path
import modal
from modal_rgec_native import execute, sha, write
from modal_rgec_residual import collect


def main(root, quiet=False):
    root.mkdir(parents=True,exist_ok=False)
    toolchain=Path('runs/rgec-modal-cas-toolchain-2026-10-04')
    baseline=json.loads((toolchain/'evidence.json').read_text())
    assert baseline['cleanup_returncode']==137 and baseline['experiment_cases']==0
    result={'platform':'Modal','gpu':None,'toolchain':baseline,'sandboxes':[],
        'source_sha256':{},'captured_project_inputs':{},'original_capture_keys':{}}
    files={}
    for cwd,name in (('/src/zlib','adler32.c'),('/src/zlib','deflate.c'),('/src/libfuzzer','FuzzerUtil.cpp')):
        path=Path('runs/rgec-modal-residual-state-2026-10-04-v17/capture')/(name+'-pristine.key')
        data=path.read_bytes();result['original_capture_keys'][str(path)]=sha(data);at=[0]
        def number():v=struct.unpack_from('<Q',data,at[0])[0];at[0]+=8;return v
        def field():n=number();v=data[at[0]:at[0]+n];at[0]+=n;assert len(v)==n;return v
        for _ in range(number()):field()
        field();count=number();number();sources=[]
        for _ in range(1,count):
            number();isfile=number();number();number()
            if not isfile:number();number();sources.append(None)
            else:sources.append((field().decode(),field()))
        assert data[at[0]:at[0]+6]==b'RGECS3';at[0]+=6;field();number()
        for source in sources:
            if source is None:number();continue
            file_backed=number();number();number()
            label,contents=source
            normalized=posixpath.normpath(label if label.startswith('/') else cwd+'/'+label)
            if file_backed and normalized.startswith(('/src/zlib/','/src/libfuzzer/')):
                if normalized in files:assert files[normalized]==contents,normalized
                files[normalized]=contents
        assert files[cwd+'/'+name]==path.with_name(name+'-pristine.source').read_bytes()
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as archive:
        for name,contents in sorted(files.items()):
            info=tarfile.TarInfo(name.lstrip('/'));info.size=len(contents);info.mode=0o644
            archive.addfile(info,io.BytesIO(contents));result['captured_project_inputs'][name]=sha(contents)
    (root/'project-inputs.tar.gz').write_bytes(buffer.getvalue())
    paths=[Path(__file__),Path('scripts/rgec_native_cas_probe.py'),Path('scripts/rgec_backend_probe.py'),
        Path('scripts/rgec_native_effect_probe.py'),Path('scripts/rgec_native_event_probe.py'),
        Path('src/unauthorized_channels/modal_recipient_entry.py'),Path('modal_rgec_native.py'),Path('modal_rgec_residual.py')]
    for path in paths:(root/path.name).write_bytes(path.read_bytes());result['source_sha256'][str(path)]=sha(path.read_bytes())
    try:
        with modal.enable_output(),modal.App('rgec-real-native-cas-baseline').run() as app:
            sb=modal.Sandbox.create('/bin/sleep','infinity',app=app,image=modal.Image.from_id(baseline['image_id']),
                cpu=2,memory=4096,timeout=1800,block_network=True)
            row={'phase':'native-cas','id':sb.object_id,'image_id':baseline['image_id']};result['sandboxes'].append(row)
            try:
                code,out,error=execute(sb,'/usr/bin/sha256sum',baseline['compiler'])
                assert code==0 and out.decode().split()[0]==baseline['compiler_sha256'],error
                write(sb,'/project-inputs.tar.gz',buffer.getvalue())
                code,_,error=execute(sb,'/usr/bin/python3','-I','-c',
                    "import tarfile; a=tarfile.open('/project-inputs.tar.gz'); assert all(m.isfile() and m.name.startswith('src/') and '..' not in m.name.split('/') for m in a.getmembers()); a.extractall('/')")
                assert code==0,error
                code,out,error=execute(sb,'/usr/bin/sha256sum',*files)
                assert code==0 and {line.split()[1]:line.split()[0] for line in out.decode().splitlines()}==result['captured_project_inputs'],error
                for path in paths[1:6]:write(sb,'/'+path.name,(root/path.name).read_bytes())
                code,_,error=execute(sb,'/bin/mkdir','-p','/workspace');assert code==0,error
                code,out,error=execute(sb,'/usr/bin/python3','-I','/rgec_native_cas_probe.py',
                    *(['silent'] if quiet else []),timeout=1200)
                row['returncode']=code;(root/'native-cas.stdout').write_bytes(out);(root/'native-cas.stderr').write_bytes(error)
                row['raw_archive_sha256']=collect(sb,root,'native-cas');assert code==0,error[-3000:]
            finally:
                sb.terminate()
                try:sb.wait()
                except modal.exception.SandboxTerminatedError:pass
                row['cleanup_returncode']=sb.returncode
    except Exception as error:result['error']=str(error);raise
    finally:(root/'evidence.json').write_text(json.dumps(result,indent=2))


if __name__=='__main__':main(Path(sys.argv[1]),len(sys.argv)>2 and sys.argv[2]=='silent')
