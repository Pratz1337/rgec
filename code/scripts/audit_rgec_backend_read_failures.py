"""Audit retained native failure controls without executing a compiler."""
import collections
import hashlib
import json
from pathlib import Path
import sys
import tarfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO/'src/unauthorized_channels'))
sys.path.insert(0, str(REPO/'scripts'))
from rgec_backend_probe import queue_signature
from rgec_native_effect_probe import signature


def sha(data): return hashlib.sha256(data).hexdigest()


for argument in sys.argv[1:]:
    root=Path(argument);manifest=json.loads((root/'evidence.json').read_text());counts=collections.Counter()
    for path,expected in manifest['source_sha256'].items():
        assert sha((root/Path(path).name).read_bytes())==expected;counts['frozen_source_snapshots']+=1
    for sandbox in manifest['sandboxes']:
        assert sandbox['returncode']==0 and sandbox['cleanup_returncode']==137
        folder=root/sandbox['phase'];archive=folder/'raw.tar.gz'
        assert sha(archive.read_bytes())==sandbox['raw_archive_sha256']
        with tarfile.open(archive) as stream:
            for member in stream:
                assert member.isfile() and member.name=='raw/'+Path(member.name).name
                assert stream.extractfile(member).read()==(folder/Path(member.name).name).read_bytes()
                counts['archive_members']+=1
        phase=json.loads((folder/'evidence.json').read_text());findings=[]
        def checked(filename,expected):
            data=(folder/filename).read_bytes();assert sha(data)==expected,filename
            counts['recorded_raw_hashes']+=1;return data
        def trace(row):
            for k,suffix in {'stdout_sha256':'.stdout','stderr_sha256':'.stderr','control_sha256':'.control',
                'held_fd_content_sha256':'.held.o','object_sha256':'.object.o'}.items():
                if row.get(k) is not None:checked(row['case']+suffix,row[k])
            counts['native_observations']+=1
        for binding in phase['bindings']:
            for role in ('native','record'):trace(binding[role])
            source=checked(binding['source']+'.original',binding['source_sha256'])
            assert source==(REPO/'runs/rgec-modal-authority-cold-warm-2026-10-04-v3'/(binding['source']+'.original')).read_bytes()
            for k,suffix in {'producer_packet_sha256':'.producer.packet','producer_stderr_sha256':'.producer.stderr'}.items():
                checked(binding['source']+suffix,binding[k])
            assert binding['producer_info']['reusable'] and binding['producer_returncode']==0
        for case in phase['cases']:
            traces=case['traces'];first=traces['native-1'];crash_sources=[]
            for row in traces.values():
                trace(row)
                preprocessed=[]
                stderr=(folder/(row['case']+'.stderr')).read_bytes()
                for remote,record in row['crash_files'].items():
                    # Labels contain the observation role and the request mode separately.
                    label=row['case'].rsplit('-',1)[0] if row['case'].endswith(('-native','-replay')) else row['case'][:-len('-wrapped-cold')]
                    data=checked(label+'-'+Path(remote).name,record['sha256'])
                    assert len(data)==record['bytes'] and remote.encode() in stderr
                    counts['native_crash_files']+=1
                    if Path(remote).suffix in ('.c','.cpp'):preprocessed.append(sha(data))
                assert len(preprocessed)==1
                crash_sources+=preprocessed
            derived={'native_repeat_stderr_equal':first['stderr_sha256']==traces['native-2']['stderr_sha256'],
                'wrapped_cold_replay_stderr_equal':traces['wrapped-cold']['stderr_sha256']==traces['replay']['stderr_sha256'],
                'all_native_statuses_equal':len({row['returncode'] for row in traces.values()})==1,
                'no_wrapped_query':all(not traces[role]['key_sha256'] for role in ('wrapped-cold','replay')),
                'measured_structures_equal':all(signature(row)==signature(first) for row in traces.values()),
                'measured_root_event_roles_equal':all(queue_signature(row['events'])==queue_signature(first['events']) for row in traces.values())}
            for k,value in derived.items():assert case[k]==value
            assert all(not (folder/(traces[role]['case']+'.control')).read_bytes() for role in ('wrapped-cold','replay'))
            findings.append({'source':case['source'],'fault':case['fault'],**derived,
                'preprocessed_crash_source_bytes_equal':len(set(crash_sources))==1,
                'native_statuses':[row['returncode'] for row in traces.values()]})
        result={'root':str(root),'manifest_sha256':sha((root/'evidence.json').read_bytes()),
            'counts':dict(counts),'findings':findings,'literal_stream_conformance_claimed':False}
        (root/'independent-failure-audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(result,indent=2))
