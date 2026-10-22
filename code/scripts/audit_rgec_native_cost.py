"""Reconcile retained real native controls and call-cost records on Modal."""
import collections
import hashlib
import json
from pathlib import Path
import random
import re
import statistics
import struct
import sys
import tarfile

def sha(data): return hashlib.sha256(data).hexdigest()
def read(path): return json.loads(path.read_text())
def quantile(values, fraction):
    values=sorted(values); return values[int((len(values)-1)*fraction)] if values else None

def codes(header):
    text=re.sub(r'/\*.*?\*/|//[^\n]*','',header,flags=re.S)
    body=text.split('enum NodeType {',1)[1].split('};',1)[0]; result={}; value=-1
    for field in body.split(','):
        if not field.strip(): continue
        match=re.fullmatch(r'(\w+)(?:\s*=\s*(-?\d+))?',field.strip()); assert match,field
        name,explicit=match.groups(); value=int(explicit) if explicit else value+1; result[value]=name
    return result

def main(root):
    manifest=read(root/'evidence.json'); terminal=read(root/'result.json'); raw=root/'raw'
    assert terminal['returncode']==manifest['sandbox']['returncode']==manifest['sandbox']['cleanup_returncode']==0
    for path,digest in manifest['source_sha256'].items(): assert sha((root/Path(path).name).read_bytes())==digest
    for path,digest in manifest['generated_sha256'].items(): assert sha((root/path).read_bytes())==digest
    for name in ('raw.tar.gz','stdout','stderr'): assert sha((root/name).read_bytes())==terminal[name+'_sha256']
    with tarfile.open(str(root/'raw.tar.gz')) as archive:
        members=archive.getmembers(); assert len({m.name for m in members})==len(members)
        for member in members:
            p=Path(member.name); assert member.isfile() and p.parts[0]=='raw' and '..' not in p.parts
            assert archive.extractfile(member).read()==(root/p).read_bytes()
    evidence=read(raw/'evidence.json'); config=read(root/'knownbits-scope-config.json')
    arms=config.get('arms',[dict(name=None,flags=config['flags'])])
    arm_names=[a['name'] for a in arms]; assert len(set(arm_names))==len(arms)
    assert evidence['suite_complete'] and len(evidence['rows'])==config['blocks']*3*len(arms) and len(evidence['held_out'])==3*len(arms)
    if 'tool_sha256' in config: assert evidence['tool_sha256']==config['tool_sha256']
    assert sha((raw/'native-bindings.json').read_bytes())==evidence['native_bindings_sha256']
    binding=read(raw/'native-bindings.json'); proof=(raw/'native-proof.elf').read_bytes()
    patched=Path('/rgec-knownbits-scope').read_bytes()
    assert sha(proof)==binding['unpatched_sha256']==evidence['tool_sha256']['/rgec-knownbits-proof']
    assert sha(patched)==binding['patched_sha256']==evidence['tool_sha256']['/rgec-knownbits-scope']
    change,=binding['changes']; pos=change['file_offset']; before=bytes.fromhex(change['original_hex']); after=bytes.fromhex(change['patched_hex'])
    assert len(before)==len(after)==5 and before[0]==after[0]==0xe8
    assert proof[pos:pos+5]==before and patched==proof[:pos]+after+proof[pos+5:]
    assert change['pc']+5+struct.unpack('<i',before[1:])[0]==change['old_target']
    assert change['pc']+5+struct.unpack('<i',after[1:])[0]==change['new_target']
    for region in binding['regions']:
        start,size=region['file_offset'],region['size']; assert sha(patched[start:start+size])==region['sha256']
    assert sha((root/'clang_knownbits_cost_census.cpp').read_bytes())==evidence['tool_sha256']['/clang_knownbits_cost_census.cpp']
    compiler_actions=plans=pairs=0; costs=collections.defaultdict(list); expected_census={}
    for row in evidence['rows']:
        arm=row.get('arm'); assert arm in arm_names
        if 'arms' in config:
            flags=next(a['flags'] for a in arms if a['name']==arm); assert row['flags']==flags
        actions=[json.loads(line) for line in (raw/row['label']/'actions.jsonl').read_text().splitlines()]
        assert actions==row['compiler_actions'] and len(actions)==23
        assert sum(a['plan'] is not None for a in actions)==19
        compiler_actions+=len(actions); plans+=19
        for action in actions:
            assert action['returncode']==0
            if action['plan']:
                if row['mode']=='census': expected_census[row['label']+'/'+action['label']+'.census']=arm
                if 'arms' in config:
                    assert all(f in action['driver_arguments'] for f in flags)
                    for flag in ('-fsanitize=address','-fsanitize-address-use-after-scope','-fsanitize=fuzzer-no-link'):
                        assert (flag in action['driver_arguments'])==(flag in flags)
            for suffix in ('stdout','stderr'):
                assert sha((raw/row['label']/(action['label']+'.'+suffix)).read_bytes())==action[suffix+'_sha256']
                if action['plan']: assert sha((raw/row['label']/(action['label']+'.plan.'+suffix)).read_bytes())==action['plan'][suffix+'_sha256']
        for name,item in row['artifacts'].items():
            body=(raw/(row['label']+'-artifact-'+name.replace('/','__'))).read_bytes()
            assert sha(body)==item['sha256'] and len(body)==item['bytes']
        for phase in [row['configure'],row['build'],row['tests']]+[p[k] for p in row['roundtrips'] for k in ('encode','decode')]:
            assert phase['returncode']==0
            for suffix in ('stdout','stderr'): assert sha((raw/(phase['label']+'.'+suffix)).read_bytes())==phase[suffix+'_sha256']
        key=arm+'/'+row['mode'] if arm is not None else row['mode']
        costs[key].append(dict(cpu=row['build']['child_cpu_seconds']+row['build']['controller_cpu_seconds'],wall=row['build']['wall_seconds']))
    for block in range(config['blocks']):
        block_rows=[r for r in evidence['rows'] if r['block']==block]
        if 'arms' in config:
            arm_order=list(arm_names); random.Random(evidence['seed']+block).shuffle(arm_order)
            assert evidence['arm_order'][block]==arm_order
            assert [r['arm'] for r in block_rows]==[a for a in arm_order for _ in range(3)]
        for index,arm in enumerate(arm_names):
            order=['original','native','census']
            seed=evidence['seed']+100*(block+1)+index if 'arms' in config else evidence['seed']+block
            random.Random(seed).shuffle(order)
            rows=[r for r in block_rows if r.get('arm')==arm]; assert [r['mode'] for r in rows]==order
            reference=next(r for r in rows if r['mode']=='original')
            for row in rows:
                assert row['order']==order.index(row['mode']) and row['artifacts']==reference['artifacts']
                assert all(all(a[k]==b[k] for k in ('returncode','stdout_sha256','stderr_sha256')) for a,b in zip(row['compiler_actions'],reference['compiler_actions']))
                assert all(row['tests'][k]==reference['tests'][k] for k in ('returncode','stdout_sha256','stderr_sha256'))
                assert row['roundtrips'] and all(all(a[k]==b[k] for k in ('input_sha256','decoded_sha256','compressed_sha256','compressed_bytes')) for a,b in zip(row['roundtrips'],reference['roundtrips']))
                if row['mode']!='original': assert all(row['reference_checks'].values()); pairs+=1
    assert len(evidence['plans'])==len(arms)
    for plan in evidence['plans']:
        assert plan['returncode']==0
        for suffix in ('stdout','stderr'): assert sha((raw/(plan['label']+'.'+suffix)).read_bytes())==plan[suffix+'_sha256']
        if 'arms' in config:
            flags=next(a['flags'] for a in arms if a['name']==plan['arm'])
            assert plan['argv'][1:1+len(flags)]==flags
    for arm in arm_names:
        rows=[r for r in evidence['held_out'] if r.get('arm')==arm]
        assert [r['variant'] for r in rows]==['original','native','census']
        reference=rows[0]
        for row in rows:
            assert all(row[k]==reference[k] for k in ('returncode','stdout_sha256','stderr_sha256','object_sha256')) and row['returncode']==0
            for suffix in ('stdout','stderr'): assert sha((raw/(row['label']+'.'+suffix)).read_bytes())==row[suffix+'_sha256']
            assert sha((raw/(row['label']+'.o')).read_bytes())==row['object_sha256']
            if row['variant']=='census': expected_census[row['label']+'.census']=arm
    names=codes((raw/'installed-ISDOpcodes.h').read_text()); families=collections.defaultdict(list); answers=collections.defaultdict(set)
    total=outer_total=nested_total=migrations=0; files=[]; examples=[]; arm_counts=collections.defaultdict(collections.Counter)
    assert {p.relative_to(raw).as_posix() for p in raw.rglob('*.census')}==set(expected_census)
    for path in sorted(raw.rglob('*.census')):
        arm=expected_census[path.relative_to(raw).as_posix()]
        body=path.read_bytes(); assert len(body)%160==0
        records=list(struct.iter_unpack('<20Q',body)); calibration=records[:64]; samples=records[64:]
        assert all(r[0]==0x524745434b435331 and r[1]==0 and r[2]==i for i,r in enumerate(calibration))
        assert all(r[0]==0x524745434b435331 and r[1]==1 for r in samples)
        metrics=struct.unpack('<12Q',path.with_suffix('.metrics').read_bytes())
        assert len(samples)==metrics[0] and len({r[2] for r in samples})==len(samples)
        assert {r[2] for r in samples}==set(range(1,len(samples)+1))
        assert sum(r[18]<=64 for r in samples)==metrics[1] and sum(r[18]>64 for r in samples)==metrics[4]
        # Entry sequence and completion order identify nested wrapper windows.
        # Only forest roots count toward an inclusive total, avoiding double count.
        root_id=1; group=[]; outer=[]; nested=0
        for record in samples:
            group.append(record)
            if record[2]!=root_id: continue
            high=max(r[2] for r in group)
            assert {r[2] for r in group}==set(range(root_id,high+1))
            outer.append(record); nested+=len(group)-1; root_id=high+1; group=[]
        assert not group and len(outer)+nested==len(samples)
        total+=len(samples); outer_total+=len(outer); nested_total+=nested
        counts=arm_counts[arm if arm is not None else 'default']
        counts.update(all_sample_records=len(samples),outer_sample_records=len(outer),nested_wrapped_records=nested)
        for r in outer:
            if r[16]!=r[17]: migrations+=1; counts['cpu_migration_outer_records']+=1; continue
            if not (r[6]==0 and r[7]==1 and r[8]==1 and not r[19] and r[18]<=64): continue
            mask=(1<<r[18])-1; assert not r[10]&r[11] and (r[10]|r[11])<=mask
            family=(arm,r[3],r[4],r[12],r[13],r[14],r[5]); families[family].append(r[15]); answers[family].add((r[10],r[11],r[18]))
            examples.append(dict(arm=arm,file=path.relative_to(raw).as_posix(),sequence=r[2],opcode=names.get(r[3],str(r[3])),
                width=r[4],children=[names.get(r[12],str(r[12])),names.get(r[13],str(r[13]))],
                zero=r[10],one=r[11],window_cycles=r[15]))
        stable=[r[15] for r in calibration if r[16]==r[17]]
        files.append(dict(arm=arm,path=path.relative_to(raw).as_posix(),sha256=sha(body),calls=len(samples),outer_calls=len(outer),nested_calls=nested,
            calibration_median_cycles=statistics.median(stable) if stable else None,calibration_same_cpu_samples=len(stable)))
    summary=[]
    for family,values in families.items():
        arm,op,width,left,right,count,result=family
        summary.append(dict(arm=arm,opcode=op,name=names.get(op,str(op)),width=width,children=[names.get(left,str(left)),names.get(right,str(right))],
            operands=count,result_number=result,samples=len(values),observed_answer_variants=len(answers[family]),
            nonunknown_answer_variants=sum(z!=0 or o!=0 for z,o,w in answers[family]),window_cycles_median=statistics.median(values),
            window_cycles_p90=quantile(values,.9),window_cycles_p99=quantile(values,.99),window_cycles_total=sum(values)))
    summary.sort(key=lambda r:r['window_cycles_total'],reverse=True)
    output=dict(manifest_sha256=sha((root/'evidence.json').read_bytes()),archive_sha256=sha((root/'raw.tar.gz').read_bytes()),
        auditor_sha256=sha(Path(__file__).read_bytes()),archive_members=len(members),native_compiler_actions=compiler_actions+len(evidence['held_out']),
        separately_counted_driver_plans=plans+len(evidence['plans']),configure_and_image_compiler_actions_additional=True,
        complete_zlib_workflows=len(evidence['rows']),complete_workflow_pairs=pairs,held_out_pairs=2*len(arms),real_file_roundtrips=len(evidence['rows'])*3,
        all_sample_records=total,outer_sample_records=outer_total,nested_wrapped_records=nested_total,cpu_migration_outer_records=migrations,
        flag_arms=arms,arm_sample_counts=arm_counts,
        census_files=files,scalar_depth0_same_cpu_outer_families=summary,
        largest_nonconstant_samples=sorted([r for r in examples if r['opcode'] not in ('Constant','TargetConstant') and (r['zero'] or r['one'])],key=lambda r:r['window_cycles'],reverse=True)[:24],
        build_cost_observations=costs,auditor_compiler_actions=0,certified_reusable_region=False,adaptive_noninterference_proved=False,substantial_novelty_established=False,
        limits=['RDTSCP windows include timer overhead, preemption and nested wrapper logging; no invariant frequency or CPU-time conversion is established',
            'Only wrapped entry calls are enumerated; unwrapped native recursion executes inside these windows',
            'Result variation and observed cost are candidate selection, not a semantic certificate or cache speedup',
            'Two randomized zlib blocks and one C++ source on one worker are not independent population samples'])
    (root/'independent-native-cost-audit.json').write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps({k:output[k] for k in ('native_compiler_actions','complete_zlib_workflows','all_sample_records','outer_sample_records','nested_wrapped_records')}))
    print(json.dumps(summary[:12],indent=2))

if __name__=='__main__':main(Path(sys.argv[1]))
