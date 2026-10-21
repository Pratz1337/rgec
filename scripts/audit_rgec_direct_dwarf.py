"""Audit actual DWARF artifacts, retaining missing prerequisites and raw failures."""
import collections
import hashlib
import json
from pathlib import Path
import struct
import sys
import tarfile


def sha(data):return hashlib.sha256(data).hexdigest()


for argument in sys.argv[1:]:
    root=Path(argument);manifest=json.loads((root/'evidence.json').read_text());counts=collections.Counter()
    for name,expected in manifest['source_sha256'].items():
        assert sha((root/Path(name).name).read_bytes())==expected;counts['frozen_sources']+=1
    for sandbox in manifest['sandboxes']:
        assert sandbox['cleanup_returncode']==137
        folder=root/sandbox['phase'];archive=folder/'raw.tar.gz'
        assert sha(archive.read_bytes())==sandbox['raw_archive_sha256']
        with tarfile.open(archive) as stream:
            for member in stream:
                assert member.isfile() and member.name=='raw/'+Path(member.name).name
                assert stream.extractfile(member).read()==(folder/Path(member.name).name).read_bytes()
                counts['archive_members']+=1
        evidence=json.loads((folder/'evidence.json').read_text())
        def checked(filename,expected):
            raw=(folder/filename).read_bytes();assert sha(raw)==expected,filename
            counts['raw_hashes']+=1;return raw
        if sandbox['returncode']!=0:
            assert sandbox['returncode']==1 and not evidence['cases'] and 'native_side' in manifest['error']
            assert (folder/'adler32.c-direct-dwo-native.object.o').read_bytes()==(folder/'adler32.c-direct-dwo-record.object.o').read_bytes()
            counts['incomplete_case_native_observations']=2
            continue
        for case in evidence['cases']:
            for mode in ('native','record','replay'):
                row=case[mode];label=row['case']
                assert row['returncode']==0
                for suffix,key in (('stdout','stdout_sha256'),('stderr','stderr_sha256'),('control','control_sha256'),
                                   ('object.o','object_sha256'),('held.o','held_fd_content_sha256')):
                    checked(label+'.'+suffix,row[key])
                counts['actual_compiler_observations']+=1
            native,record,replay=case['native'],case['record'],case['replay']
            assert all(native[key]==record[key]==replay[key] for key in
                ('returncode','stdout_sha256','stderr_sha256','object_sha256'))
            assert case['status_stream_object_match'] and case['structural_effects_match']
            assert case['native_side']==case['record_side']==case['replay_side'] and case['side_output_matches']
            if case['native_side']:
                for mode in ('native','record','replay'):
                    raw=checked(case['name']+'-'+mode+'.dwo',case[mode+'_side']['sha256'])
                    assert len(raw)==case[mode+'_side']['bytes'] and raw[:4]==b'\x7fELF'
                counts['actual_driver_dwo_groups']+=1
            else:
                assert not case['direct_side_stream_exercised'];counts['no_native_standalone_dwo']+=1
            control=(folder/(replay['case']+'.control')).read_bytes()
            assert control[:6]==b'RGECQ1'
            length=struct.unpack_from('<Q',control,6)[0]
            assert sha(control[14:14+length])==replay['key_sha256']
            assert control[14+length:]==b'RGECH1'==replay['receipt'].encode()
            counts['native_value_comparisons']+=1
            counts['reported_event_role_matches']+=case['event_roles_match']
            counts['reported_event_role_mismatches']+=not case['event_roles_match']
        assert len(evidence['cases'])==9 and counts['actual_driver_dwo_groups']==3
    result={'root':str(root),'manifest_sha256':sha((root/'evidence.json').read_bytes()),
        'counts':dict(counts),'suite_complete':'error' not in manifest,
        'native_direct_side_stream_exercised':False,'general_side_effect_closure_certified':False}
    (root/'independent-dwarf-audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))
