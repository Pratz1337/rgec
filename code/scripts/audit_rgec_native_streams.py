"""Independently audit retained native compiler failures and libc transcripts."""
import collections
import hashlib
import json
from pathlib import Path
import random
import struct
import sys
import tarfile


def sha(data): return hashlib.sha256(data).hexdigest()


def trace(data):
    cursor = 0; rows = []
    while cursor < len(data):
        assert cursor + 64 <= len(data), ('partial trace header', cursor)
        magic, kind, fd, count, offset, result, error, length = struct.unpack_from('<8q', data, cursor)
        assert magic == 0x5247454354524331 and kind in range(6), ('trace framing', cursor)
        assert 0 <= length <= 4096 and fd >= 0 and error >= 0
        cursor += 64
        path = data[cursor:cursor + length]; assert len(path) == length; cursor += length
        payload = b''
        if kind in (0, 3, 4):
            assert count >= 0 and -1 <= result <= count
            payload = data[cursor:cursor + count]; assert len(payload) == count; cursor += count
        rows.append({'kind': kind, 'fd': fd, 'count': count, 'offset': offset,
            'result': result, 'errno': error, 'path': path.decode(errors='replace'),
            'payload_sha256': sha(payload) if kind in (0, 3, 4) else None})
    return rows


def effects(row):
    path, = row['paths']; before = row['before'][path]; after = row['after'][path]
    return {'output': {k:v for k,v in after.items() if k not in ('ino','mtime_ns','ctime_ns')},
        'inode_changed': before.get('ino') != after.get('ino'),
        'entries': row['directory_entries_after']}


def event_roles(row):
    return [{'mask': e['mask'], 'role': 'temporary' if e['name'].endswith('.tmp') else e['name']} for e in row['events']]


def compare(left, right):
    return {'returncode':left['returncode'] == right['returncode'],
        'status_and_streams': all(left[k] == right[k] for k in ('returncode','stdout_sha256','stderr_sha256')),
        'object':left['object_sha256'] == right['object_sha256'],
        'structural_effects':effects(left) == effects(right), 'event_roles':event_roles(left) == event_roles(right)}


def main(root):
    manifest_bytes = (root / 'evidence.json').read_bytes(); m = json.loads(manifest_bytes)
    worker = m['sandbox']; assert worker['returncode'] == worker['cleanup_returncode'] == 0
    for name, expected in m['source_sha256'].items():
        assert sha((root / name.replace('\\','/').split('/')[-1]).read_bytes()) == expected
    assert sha((root/'stream-config.json').read_bytes()) == m['config_sha256']
    assert sha((root/'baseline-evidence.json').read_bytes()) == m['baseline_manifest_sha256']
    baseline = json.loads((root/'baseline-evidence.json').read_bytes())
    old_tools=baseline['sandboxes'][0]['tool_sha256']
    if m.get('build_native'):
        assert m['native_recompilations']==1 and m['build_fingerprint_returncode']==0
        assert sha((root/'native-build.py').read_bytes())==m['build_script_sha256']
        assert json.loads((root/'build-fingerprint.stdout').read_bytes())==m['native_tool_sha256']
        for path,expected in old_tools.items():
            if path not in ('/rgec-backend','/rgec-backend.cpp'):
                assert m['native_tool_sha256'][path]==expected
        assert m['native_tool_sha256']['/rgec-backend']!=old_tools['/rgec-backend']
        assert m['native_tool_sha256']['/rgec-backend.cpp']==sha((root/'clang_backend_continuation.cpp').read_bytes())
    else: assert old_tools == m['native_tool_sha256']
    durable = json.loads((root/'durable-result.json').read_bytes())
    assert durable['returncode'] == 0 and durable['tool_sha256'] == m['native_tool_sha256']
    assert durable['raw.tar.gz_sha256'] == worker['raw_archive_sha256']
    for name in ('raw.tar.gz','stdout','stderr'):
        assert sha((root/name).read_bytes()) == durable[name+'_sha256']
    with tarfile.open(root/'raw.tar.gz') as archive:
        members = archive.getmembers(); assert len({v.name for v in members}) == len(members)
        for member in members:
            assert member.isfile() and member.name == 'raw/' + Path(member.name).name
            assert archive.extractfile(member).read() == (root/member.name).read_bytes()
    raw = root/'raw'; e=json.loads((raw/'evidence.json').read_bytes())
    assert e['suite_complete'] and len(e['rows']) == 192 and len(e['primes']) == len(e['plans']) == 3
    assert e['tracer_build']['returncode'] == 0
    assert sha((root/'rgec_native_stream_trace.c').read_bytes()) == e['tracer_build']['source_sha256']
    assert sha((raw/'rgec-stream-trace.so').read_bytes()) == e['tracer_build']['binary_sha256']
    rng = random.Random(e['seed']); indexed={}; transcripts={}; errors=[]
    for source in e['sources']:
        original=(raw/(source['source']+'.original')).read_bytes()
        assert sha(original) == source['source_sha256']
        assert original == (root/('baseline-'+source['source']+'.original')).read_bytes()
        prime=next(p for p in e['primes'] if p['source']==source['source'])
        packet=(raw/(source['source']+'.packet')).read_bytes()
        assert prime['returncode'] == 0 and prime['packet_info']['reusable']
        assert sha(packet) == prime['control_sha256']
        # Parse every actual operation independently of the producer's summary.
        assert packet[:6] == b'RGECB1'
        cursor=6
        def number():
            nonlocal cursor
            value,=struct.unpack_from('<Q',packet,cursor); cursor+=8; return value
        def field():
            nonlocal cursor
            size=number(); data=packet[cursor:cursor+size]; assert len(data)==size; cursor+=size; return data
        bound=field(); assert number()==1
        for _ in range(number()): number(); number(); field(); field()
        operations=[]
        for _ in range(number()):
            kind=number(); offset=number(); data=field()
            operations.append({'kind':kind,'offset':offset,'bytes':len(data),'sha256':sha(data)})
        assert cursor==len(packet) and operations==prime['packet_info']['operations']
        for block in range(2):
            for fault in ('regular','dev-full','file-size-signal','file-size-error'):
                order=[(mode,traced) for mode in ('native','wrapped','record','replay') for traced in (False,True)]
                rng.shuffle(order)
                for index,(mode,traced) in enumerate(order):
                    row=next(r for r in e['rows'] if (r['source'],r['block'],r['fault'],r['mode'],r['traced'])==(source['source'],block,fault,mode,traced))
                    assert row['order']==index and row['argv'][1:]==source['cc1']
                    label=row['label']; indexed[(source['source'],block,fault,mode,traced)]=row
                    for suffix in ('control','stdout','stderr'):
                        assert sha((raw/(label+'.'+suffix)).read_bytes()) == row[suffix+'_sha256']
                    if row['object_sha256'] is not None: assert sha((raw/(label+'.object.o')).read_bytes())==row['object_sha256']
                    control=(raw/(label+'.control')).read_bytes()
                    if mode=='replay':
                        assert row['input_packet_sha256']==sha(packet)
                        if control.startswith(b'RGECQ1'):
                            size,=struct.unpack_from('<Q',control,6)
                            assert control[14:14+size]==bound
                            assert sha(bound)==row['key_sha256']
                            assert control[14+size:].decode()==row['receipt']
                        elif control==b'RGECP1':
                            assert row['receipt']=='RGECP1' and row['key_sha256'] is None
                            assert m.get('build_native') and fault.startswith('file-size-')
                        else: assert not control and row['returncode']!=0
                    if traced:
                        data=(raw/(label+'.trace')).read_bytes(); assert sha(data)==row['trace_sha256']
                        parsed=trace(data)
                        output=[v for v in parsed if v['path'].startswith('/workspace/backend-continuation/action/') or v['path']=='/dev/full']
                        assert output, ('no output libc calls',label)
                        transcripts[label]=output
                        for v in output:
                            if v['result']<0: errors.append({'label':label,**v})
    comparisons=[]; controls=[]; repeats=[]; stream_comparisons=[]
    for s in e['sources']:
        source=s['source']
        for block in range(2):
            for fault in ('regular','dev-full','file-size-signal','file-size-error'):
                for traced in (False,True):
                    native=indexed[(source,block,fault,'native',traced)]
                    for mode in ('wrapped','record','replay'):
                        row=indexed[(source,block,fault,mode,traced)]
                        comparisons.append({'source':source,'block':block,'fault':fault,'mode':mode,'traced':traced,**compare(native,row)})
                        if traced:
                            projection=lambda label:[{k:v for k,v in r.items() if k not in ('fd','path')} for r in transcripts[label]]
                            stream_comparisons.append({'label':row['label'],'fault':fault,'mode':mode,
                                'returned_output_call_sequence_match':projection(native['label'])==projection(row['label'])})
                for mode in ('native','wrapped','record','replay'):
                    controls.append({'source':source,'block':block,'fault':fault,'mode':mode,
                        **compare(indexed[(source,block,fault,mode,False)],indexed[(source,block,fault,mode,True)])})
        for fault in ('regular','dev-full','file-size-signal','file-size-error'):
            repeats.append({'source':source,'fault':fault,
                **compare(indexed[(source,0,fault,'native',False)],indexed[(source,1,fault,'native',False)])})
    def totals(rows):
        return {k:{'matches':sum(r[k] for r in rows),'total':len(rows)} for k in ('returncode','status_and_streams','object','structural_effects','event_roles')}
    audit={'manifest_sha256':sha(manifest_bytes),'auditor_sha256':sha(Path(__file__).read_bytes()),
        'source_snapshots':len(m['source_sha256']),'archive_members':len(members),
        'compiler_comparison_executions':192,'packet_producing_compilations':3,'native_driver_plan_calls':3,
        'actual_trace_transcripts':len(transcripts),'comparisons':comparisons,'comparison_totals':totals(comparisons),
        'trace_controls':controls,'trace_control_totals':totals(controls),'native_repeats':repeats,
        'native_repeat_totals':totals(repeats),'returned_output_call_comparisons':stream_comparisons,
        'returned_output_calls':transcripts,'failed_returned_output_calls':errors,
        'returncode_counts':[{'fault':k[0],'returncode':k[1],'count':v} for k,v in sorted(collections.Counter((r['fault'],r['returncode']) for r in e['rows']).items())],
        'complete_closure_certified':False,'adaptive_noninterference_proved':False,
        'scope':'Finite raw observations. Returned libc calls only; direct syscalls/internal aliases, non-returning signal-interrupted calls, internal flush and tell are not fully observed. No normalization of stderr or cache-dependent differences.'}
    stages={}; stage_comparisons=[]
    import re
    for key,row in indexed.items():
        text=(raw/(row['label']+'.stderr')).read_text()
        # Record this native marker as an additional explicit projection.
        # Raw stderr hashes and mismatches above remain intact.
        stages[key]=re.findall(r'^2\.\s*(.*)$',text,re.M)
    for source in e['sources']:
        for block in range(2):
            for fault in ('file-size-signal','file-size-error'):
                for traced in (False,True):
                    left=indexed[(source['source'],block,fault,'native',traced)]
                    right=indexed[(source['source'],block,fault,'replay',traced)]
                    stage_comparisons.append({'source':source['source'],'block':block,'fault':fault,'traced':traced,
                        'native_stage':stages[(source['source'],block,fault,'native',traced)],
                        'replay_stage':stages[(source['source'],block,fault,'replay',traced)],
                        'match':stages[(source['source'],block,fault,'native',traced)]==stages[(source['source'],block,fault,'replay',traced)],
                        'prequery_private_native':right['receipt']=='RGECP1'})
    audit['native_failure_stage_comparisons']=stage_comparisons
    audit['actual_prequery_private_replays']=sum(r['mode']=='replay' and r['receipt']=='RGECP1' for r in e['rows'])
    audit['actual_hits']=sum(r['mode']=='replay' and r['receipt']=='RGECH1' for r in e['rows'])
    (root/'independent-stream-audit.json').write_text(json.dumps(audit,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:audit[k] for k in ('compiler_comparison_executions','comparison_totals','trace_control_totals','native_repeat_totals')}))


if __name__=='__main__': main(Path(sys.argv[1]))
