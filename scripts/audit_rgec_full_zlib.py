"""Audit real native full-project artifacts; never compile locally."""
import collections
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tarfile


def sha(data): return hashlib.sha256(data).hexdigest()


for argument in sys.argv[1:]:
    root=Path(argument);manifest=json.loads((root/'evidence.json').read_text());counts=collections.Counter()
    for path,expected in manifest['source_sha256'].items():
        assert sha((root/Path(path).name).read_bytes())==expected;counts['frozen_source_snapshots']+=1
    partial='error' in manifest
    for row in manifest['sandboxes']:
        assert row['cleanup_returncode']==137
        assert row['returncode']==(1 if partial else 0)
        folder=root/row['phase'];archive=folder/'raw.tar.gz'
        assert sha(archive.read_bytes())==row['raw_archive_sha256']
        with tarfile.open(archive) as stream:
            for member in stream:
                assert member.isfile() and member.name=='raw/'+Path(member.name).name
                assert stream.extractfile(member).read()==(folder/Path(member.name).name).read_bytes()
                counts['archive_members']+=1
        if partial:
            assert not (folder/'evidence.json').exists()
            assert b'shlex' in (root/(row['phase']+'.stderr')).read_bytes()
            counts['native_phases_completed']=0
            continue
        phase=json.loads((folder/'evidence.json').read_text())
        def checked(filename,expected):
            data=(folder/filename).read_bytes();assert sha(data)==expected,filename
            counts['recorded_raw_hashes']+=1;return data
        for relative,expected in phase['input_sha256'].items():
            checked('input-'+relative.replace('/','__'),expected)
            counts['original_native_input_files']+=1
        assert len(phase['phases'])==9
        assert [r['argv'] for r in phase['phases'][:3]]==[['./configure','--static'],['/usr/bin/make','-j2'],['/usr/bin/make','test']]
        assert phase['environment']['CC']=='/usr/local/bin/clang' and '-fsanitize=address' in phase['environment']['CFLAGS']
        assert 'ASAN_OPTIONS' not in phase['environment']
        for command in phase['phases']:
            assert command['returncode']==0 and command['helper_wall_seconds']>0 and command['child_cpu_seconds']>=0
            checked(command['label']+'.stdout',command['stdout_sha256'])
            checked(command['label']+'.stderr',command['stderr_sha256'])
            counts['native_phases_completed']+=1
        upstream=(folder/'upstream-test.stdout').read_bytes()
        assert b'*** zlib test OK ***' in upstream and b'*** zlib 64-bit test OK ***' in upstream
        assert phase['source_bodies_unchanged'] and not phase['shared_reuse_enabled']
        for row in phase['roundtrips']:
            name=Path(row['path']).name
            original=checked('roundtrip-'+name+'.input',row['input_sha256'])
            compressed=(folder/('compress-'+name+'.stdout')).read_bytes()
            restored=(folder/('decompress-'+name+'.stdout')).read_bytes()
            assert len(original)==row['input_bytes'] and len(compressed)==row['compressed_bytes']
            assert original==restored==gzip.decompress(compressed)
            assert sha(restored)==row['decoded_sha256'] and row['bytes_equal']
            counts['actual_file_roundtrips']+=1
        for relative,record in phase['outputs'].items():
            data=checked('output-'+relative.replace('/','__'),record['sha256']);assert len(data)==record['bytes']
            if relative.endswith('.o'):
                assert data[:4]==b'\x7fELF';counts['fresh_native_objects']+=1
            elif relative in ('example','minigzip','example64','minigzip64'):
                assert data[:4]==b'\x7fELF';counts['fresh_native_executables']+=1
            elif relative=='libz.a':assert data[:8]==b'!<arch>\n';counts['fresh_native_archives']+=1
        assert counts['fresh_native_objects']==19 and counts['fresh_native_executables']==4 and counts['fresh_native_archives']==1
    result={'root':str(root),'manifest_sha256':sha((root/'evidence.json').read_bytes()),
        'suite_complete':not partial,'counts':dict(counts),'shared_policy_integrated':False}
    (root/'independent-full-zlib-audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
