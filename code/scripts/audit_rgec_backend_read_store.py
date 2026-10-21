"""Inspect real authenticated map/policy bytes; no local compiler execution."""
import collections
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tarfile

sys.dont_write_bytecode = True


def sha(data): return hashlib.sha256(data).hexdigest()


for argument in (value for value in sys.argv[1:] if value!='--read-only'):
    root=Path(argument).resolve()
    # Use the exact store/protocol readers frozen with the cloud study.
    sys.path.insert(0,str(root))
    from backend_recipe_store import computation_key,packet_key
    from rgec_backend_probe import packet_info
    evidence=json.loads((root/'evidence.json').read_text())
    assert 'error' not in evidence
    prefix_history=evidence.get('prefix_diagnostic_history_experiment',False)
    assert len(evidence['comparisons'])==(12 if prefix_history else 27)
    assert len(evidence['sandboxes'])==(8 if prefix_history else 11)
    assert all(s['cleanup_returncode']==137 for s in evidence['sandboxes'])
    for path,expected in evidence['source_sha256'].items():assert sha((root/Path(path).name).read_bytes())==expected
    archive_members=0
    traces=[]
    for archive in root.glob('*.tar.gz'):
        folder=root/archive.name.removesuffix('.tar.gz')
        with tarfile.open(archive) as stream:
            for member in stream:
                assert member.isfile() and member.name==Path(member.name).name
                assert stream.extractfile(member).read()==(folder/member.name).read_bytes()
                archive_members+=1
        trace=json.loads((folder/'trace.json').read_text())
        for suffix in ('stdout','stderr'):
            assert sha((folder/('result.'+suffix)).read_bytes())==trace[suffix+'_sha256']
        assert sha((folder/'control.bin').read_bytes())==trace['control_sha256']
        if trace.get('held_fd_content_sha256'):
            assert sha((folder/'held.o').read_bytes())==trace['held_fd_content_sha256']
        for name in ('output.o','alias.o'):
            path=trace['paths'][0] if name=='output.o' else trace['paths'][1]
            state=trace['after'][path]
            if 'content_sha256' in state:
                assert sha((folder/name).read_bytes())==state['content_sha256']
            else:assert not (folder/name).exists()
        traces.append((trace,folder))
    assert len(traces)==2*len(evidence['comparisons'])
    origins={}
    producer_sizes=[]
    for path in root.glob('sb-*/origin.json'):
        origin=json.loads(path.read_text());folder=path.parent
        bound=(folder/'producer.key').read_bytes();packet=(folder/'producer.packet').read_bytes()
        assert sha(bound)==origin['captured_context_sha256'] and sha(packet)==origin['packet_sha256']
        assert origin['fresh_frontend_returncode']==1 and not origin['fresh_frontend_packet']
        assert not (folder/'fresh.control').read_bytes()
        assert b'PermissionError' in (folder/'map-open.stderr').read_bytes() and origin['map_open_returncode']==1
        reads=[];core=computation_key(bound,reads)
        assert len(reads)==1 and reads[0][0]=='/workspace/recipient/rewrite-map.yaml'
        assert sha(reads[0][1])==origin['map_bytes_sha256']
        assert packet[:6]==b'RGECB2' and packet_key(packet)==core
        assert packet_info(packet)['reusable']==origin['reusable']
        length=struct.unpack_from('<Q',packet,6)[0];assert packet[14:14+length]==bound
        delivery=b'RGECB3'+packet[14+length:]
        origins.setdefault(sha(core),set()).add(delivery)
        producer_sizes.append(len(packet))
    assert len(producer_sizes)==(6 if prefix_history else 9)
    bindings=[];profiles={};failures=[]
    for row in evidence['comparisons']:
        actual=row['actual'];folder=root/actual['request_id']
        reference=row['reference']
        trace=json.loads((folder/'trace.json').read_text())
        assert all(actual[k]==value for k,value in trace.items())
        assert sum(trace==reference for trace,_ in traces)==1
        from rgec_native_effect_probe import signature
        from rgec_backend_probe import queue_signature
        assert all(reference[k]==actual[k] for k in ('returncode','stdout_sha256','stderr_sha256'))
        assert signature(reference)==signature(actual)
        assert queue_signature(reference['events'])==queue_signature(actual['events'])
        assert all(row[k] for k in ('status_and_streams_match','structural_effects_match','queued_event_roles_match'))
        if not actual['query_emitted']:
            assert '-missing-map-before-query' in row['label'] and actual['returncode']==1
            assert not (folder/'control.bin').read_bytes()
            failures.append(row['label']);continue
        bound=(folder/'query.bin').read_bytes();reply=(folder/'reply.packet').read_bytes()
        reads=[];core=computation_key(bound,reads)
        assert sha(bound)==actual['key_sha256'] and packet_key(reply)==core
        assert actual['receipt']=='RGECH1' and reply[:6]==b'RGECB3'
        assert reply in origins[sha(core)]
        profile=actual['profile'];source=profile.split('-')[1]
        # Retained YAML and native returned bytes are the same actual input.
        version='A' if b'rgec_actual_map_A' in reads[0][1] else 'B'
        assert reads[0][1]==(root/({'adler32':'adler32.c','deflate':'deflate.c','util':'FuzzerUtil.cpp'}.get(source,'FuzzerUtil.cpp')+'-'+version+'.yaml')).read_bytes()
        profiles.setdefault(profile,{}).setdefault(version,[]).append((sha(bound),sha(core),sha(reply),actual['returncode']))
        bindings.append({'label':row['label'],'full_context_sha256':sha(bound),'computation_sha256':sha(core),
            'delivery_sha256':sha(reply),'delivery_bytes':len(reply),'recipient_status':actual['returncode']})
    assert len(bindings)==(12 if prefix_history else 21) and len(failures)==(0 if prefix_history else 6)
    for profile,versions in profiles.items():
        assert set(versions)=={'A','B'}
        assert len({core for _,core,_,_ in versions['A']})==1
        assert len({core for _,core,_,_ in versions['B']})==1
        assert versions['A'][0][1]!=versions['B'][0][1]
        for values in versions.values():
            assert len({full for full,_,_,_ in values})>=2
            assert len({packet for _,_,packet,_ in values})==1
            assert {status for _,_,_,status in values}==({0} if prefix_history else {0,1})
    routes=collections.Counter(r['route'] for r in evidence['store_audit'])
    expected_routes={'separate-producer-miss':6,'authenticated-hit':6} if prefix_history else {'separate-producer-miss':6,'authenticated-hit':12,'recomputed-invalid-entry':3}
    assert dict(routes)==expected_routes
    if prefix_history:
        for profile in profiles:
            for version in ('A','B'):
                group=[row for row in evidence['comparisons'] if row['actual']['profile']==profile and '-'+version+'-' in row['label']]
                assert len(group)==2
                expected=[]
                warning_totals={}
                for row in group:
                    stderr=(root/row['actual']['request_id']/'result.stderr').read_bytes()
                    enabled='prefix-warning' in row['label']
                    assert stderr.count(b': warning: recipient native prefix history')==(2 if enabled else 0)
                    if evidence.get('prefix_history_backend_stack_policy')=='warning':
                        assert b'[-Wframe-larger-than=]' in stderr
                        assert b'warning: stack' in stderr
                        totals=re.findall(rb'([0-9]+) warnings? generated\.',stderr)
                        assert len(totals)==1
                        warning_totals[enabled]=int(totals[0])
                    expected.append(row['actual']['stderr_sha256'])
                assert len(set(expected))==2
                if warning_totals:
                    assert warning_totals[False]>0 and warning_totals[True]==warning_totals[False]+2
    assert len(evidence['request_rejections'])==7
    result={'root':str(root),'manifest_sha256':sha((root/'evidence.json').read_bytes()),
        'authenticated_native_comparisons':len(evidence['comparisons']),'query_packet_bindings':len(bindings),'routes':dict(routes),
        'archive_members':archive_members,'native_request_traces':len(traces),'prefix_diagnostic_history_experiment':prefix_history,
        'prefix_backend_warning_interaction_verified':prefix_history and evidence.get('prefix_history_backend_stack_policy')=='warning',
        'missing_map_before_query':len(failures),'protected_inputs_per_producer':sorted({json.loads(p.read_text())['protected_files'] for p in root.glob('sb-*/origin.json')}),
        'byte_identical_delivery_groups':6,'distinct_map_computation_keys_per_profile':2,
        'recipient_statuses_from_equal_delivery':[0] if prefix_history else [0,1],'producer_packet_bytes':producer_sizes,
        'bindings':bindings,'complete_closure_certified':False,'adaptive_noninterference_proved':False}
    if '--read-only' not in sys.argv:
        (root/'independent-read-store-audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:value for key,value in result.items() if key!='bindings'},indent=2))
