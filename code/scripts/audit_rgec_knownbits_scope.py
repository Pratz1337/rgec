"""Data-only byte, native-binding, scalar-answer and complete-cost audit."""
import collections
import hashlib
import json
from pathlib import Path
import random
import re
import statistics
import struct
import subprocess
import sys
import tarfile

def sha(data): return hashlib.sha256(data).hexdigest()
def read_json(path): return json.loads(path.read_text())

def opcodes(header, kind='NodeType'):
    text = re.sub(r'/\*.*?\*/|//[^\n]*', '', header, flags=re.S)
    body = text.split('enum '+kind+' {',1)[1].split('};',1)[0]
    values = {}; value = -1
    for field in body.split(','):
        field = field.strip()
        if not field: continue
        match = re.fullmatch(r'(\w+)(?:\s*=\s*(-?\d+))?',field)
        assert match, field
        name, explicit = match.groups(); value = int(explicit) if explicit else value+1; values[name]=value
    return values

def native_formula(words, cursor, codes):
    opcode, width, result, depth = words[cursor:cursor+4]; cursor += 4
    assert 1 <= width <= 64 and depth <= 6
    all_bits = (1 << width)-1; zero = one = 0
    if opcode in (codes['Constant'],codes['TargetConstant']):
        one = words[cursor]; cursor += 1; assert one <= all_bits
        return (all_bits ^ one,one,width),cursor
    if depth == 6: return (0,0,width),cursor
    if opcode == codes['LOAD']:
        extension, memory_width = words[cursor:cursor+2]; cursor += 2
        # Actual LoadExtType enumeration retained in the installed header.
        if extension == codes['ZEXTLOAD'] and result == 0:
            assert 1 <= memory_width <= width; zero = all_bits ^ ((1 << memory_width)-1)
        else: assert memory_width == 0
        return (zero,0,width),cursor
    left,cursor = native_formula(words,cursor,codes); z,o,w = left
    if opcode in (codes['AND'],codes['OR'],codes['XOR']):
        right,cursor = native_formula(words,cursor,codes); rz,ro,rw = right; assert rw == w == width
        if opcode == codes['AND']: zero,one = z|rz,o&ro
        if opcode == codes['OR']: zero,one = z&rz,o|ro
        if opcode == codes['XOR']: zero,one = (z&rz)|(o&ro),(z&ro)|(o&rz)
    else:
        assert opcode in (codes['ZERO_EXTEND'],codes['SIGN_EXTEND'],codes['ANY_EXTEND'],codes['TRUNCATE'])
        assert (w > width) if opcode == codes['TRUNCATE'] else (w < width)
        zero,one = z&all_bits,o&all_bits; high = all_bits & ~((1 << w)-1)
        if opcode == codes['ZERO_EXTEND']: zero |= high
        if opcode == codes['SIGN_EXTEND']:
            if z & (1 << (w-1)): zero |= high
            if o & (1 << (w-1)): one |= high
    assert not zero & one and zero <= all_bits and one <= all_bits
    return (zero,one,width),cursor

def main(root):
    m=read_json(root/'evidence.json'); raw=root/'raw'; result=read_json(root/'durable-result.json')
    assert m['sandbox']['returncode']==m['sandbox']['cleanup_returncode']==result['returncode']==0
    for path,expected in m['source_sha256'].items(): assert sha((root/Path(path).name).read_bytes())==expected
    assert sha((root/'native-scope-build.py').read_bytes())==m['build_sha256']
    assert sha((root/'knownbits-scope-config.json').read_bytes())==m['config_sha256']
    for name in ('raw.tar.gz','stdout','stderr'): assert sha((root/name).read_bytes())==result[name+'_sha256']
    assert result['raw.tar.gz_sha256']==m['sandbox']['raw_archive_sha256']
    with tarfile.open(str(root/'raw.tar.gz')) as archive:
        members=archive.getmembers(); assert len({v.name for v in members})==len(members)
        for member in members:
            path=Path(member.name); assert member.isfile() and path.parts[0]=='raw' and '..' not in path.parts
            assert archive.extractfile(member).read()==(root/path).read_bytes()
    e=read_json(raw/'evidence.json'); config=read_json(root/'knownbits-scope-config.json')
    assert e['suite_complete'] and len(e['rows'])==1+config['blocks']*6 and len(e['held_out'])==7
    assert e['tool_sha256']['/usr/local/bin/clang']==config['native_sha256']
    assert e['tool_sha256']['/clang_knownbits_scope.cpp']==config['scope_source_sha256']
    binding=read_json(raw/'native-bindings.json'); assert sha((raw/'native-bindings.json').read_bytes())==e['native_bindings_sha256']
    binary=Path('/rgec-knownbits-scope').read_bytes()
    assert sha(binary)==e['tool_sha256']['/rgec-knownbits-scope']==binding['patched_sha256']
    assert len(binding['changes'])==1
    for region in binding['regions']:
        pos,size=region['file_offset'],region['size']; assert sha(binary[pos:pos+size])==region['sha256']
    change,=binding['changes']; pc=change['pc']; pos=change['file_offset']
    before=bytes.fromhex(change['original_hex']); after=bytes.fromhex(change['patched_hex'])
    assert before[0]==after[0]==0xe8 and len(before)==len(after)==5 and binary[pos:pos+5]==after
    assert pc+5+struct.unpack('<i',before[1:])[0]==change['old_target']
    assert pc+5+struct.unpack('<i',after[1:])[0]==change['new_target']
    entry=binding['regions'][1]; assert entry['address']<=pc<pc+5<=entry['address']+entry['size']
    disassembly=subprocess.check_output(['/usr/bin/objdump','-d','--start-address=%d'%entry['address'],
        '--stop-address=%d'%(entry['address']+entry['size']),'/rgec-knownbits-scope'])
    (root/'independent-native-bindings.stdout').write_bytes(disassembly)
    line,=[line for line in disassembly.decode().splitlines() if line.lstrip().startswith('%x:'%pc)]
    assert re.search(r'\bcallq\s+%x\s'%change['new_target'],line)
    header=(raw/'installed-llvm__CodeGen__ISDOpcodes.h').read_text()
    codes=opcodes(header); extensions=opcodes(header,'LoadExtType');codes.update(extensions)
    assert extensions==dict(NON_EXTLOAD=0,EXTLOAD=1,SEXTLOAD=2,ZEXTLOAD=3)
    packets=0; answers=0; shapes=collections.Counter()
    for path in raw.rglob('*.packet'):
        data=path.read_bytes(); cursor=0; packets+=1
        while cursor<len(data):
            count,width,zero,one=struct.unpack_from('<4Q',data,cursor); cursor+=32
            assert 1<=count<=512
            words=struct.unpack_from('<%dQ'%count,data,cursor); cursor+=count*8
            expected,end=native_formula(words,0,codes)
            assert expected==(zero,one,width) and end==count
            shapes[str(words[0])]+=1; answers+=1
        assert cursor==len(data)
    names=('calls','admitted','hits','misses','rejected','shadow_checks','native_disagreements','key_conflicts',
        'stored','replacements','imported','direct_evaluations')
    rng=random.Random(e['seed']); compiler_actions=plans=0; pairs=0; costs=collections.defaultdict(list)
    totals=collections.Counter()
    for row in e['rows']:
        action_rows=[json.loads(line) for line in (raw/row['label']/'actions.jsonl').read_text().splitlines()]
        assert action_rows==row['compiler_actions'] and len(action_rows)==23
        assert sum(a['plan'] is not None for a in action_rows)==19
        compiler_actions+=23; plans+=19
        local=collections.Counter()
        for path in (raw/row['label']).glob('*.metrics'):
            values=struct.unpack('<12Q',path.read_bytes()); assert values[6]==values[7]==0
            assert values[1]+values[4]<=values[0] and values[2]+values[3]<=values[1]
            local.update(dict(zip(names,values)))
        assert all(local[name]==row['metrics'][name] for name in names); totals.update(local)
        for action in action_rows:
            assert action['returncode']==0
            for suffix in ('stdout','stderr'):
                assert sha((raw/row['label']/(action['label']+'.'+suffix)).read_bytes())==action[suffix+'_sha256']
                if action['plan']: assert sha((raw/row['label']/(action['label']+'.plan.'+suffix)).read_bytes())==action['plan'][suffix+'_sha256']
        for name,value in row['artifacts'].items():
            data=(raw/(row['label']+'-artifact-'+name.replace('/','__'))).read_bytes()
            assert len(data)==value['bytes'] and sha(data)==value['sha256']
        for phase in [row['configure'],row['build'],row['tests']]+[p[k] for p in row['roundtrips'] for k in ('encode','decode')]:
            assert phase['returncode']==0
            for suffix in ('stdout','stderr'): assert sha((raw/(phase['label']+'.'+suffix)).read_bytes())==phase[suffix+'_sha256']
            assert phase['child_cpu_seconds']>=-1e-12 and phase['controller_cpu_seconds']>=-1e-12 and phase['wall_seconds']>0
        variant=row.get('variant','producer-shadow')
        costs[variant].append(dict(cpu=row['build']['child_cpu_seconds']+row['build']['controller_cpu_seconds'],wall=row['build']['wall_seconds']))
    for block in range(config['blocks']):
        order=['original','native','guard','cache-cold','cache-peer','direct'];rng.shuffle(order)
        rows=[r for r in e['rows'] if r.get('block')==block]; assert [r['variant'] for r in rows]==order
        reference=next(r for r in rows if r['variant']=='original')
        for row in rows:
            assert row['order']==order.index(row['variant']) and row['artifacts']==reference['artifacts']
            assert all(row['reference_checks'].values()); pairs+=row['variant']!='original'
            assert all(all(a[k]==b[k] for k in ('returncode','stdout_sha256','stderr_sha256'))
                for a,b in zip(row['compiler_actions'],reference['compiler_actions']))
            assert all(row['tests'][k]==reference['tests'][k] for k in ('returncode','stdout_sha256','stderr_sha256'))
            assert all(all(a[k]==b[k] for k in ('input_sha256','decoded_sha256','compressed_sha256','compressed_bytes'))
                for a,b in zip(row['roundtrips'],reference['roundtrips']))
    producer=e['rows'][0]
    assert producer['label']=='producer-shadow' and producer['metrics']['shadow_checks']==producer['metrics']['admitted']>0
    assert all(producer['reference_checks'].values())
    reference=next(r for r in e['rows'] if r.get('variant')=='original')
    assert producer['artifacts']==reference['artifacts']
    assert all(all(a[k]==b[k] for k in ('returncode','stdout_sha256','stderr_sha256'))
        for a,b in zip(producer['compiler_actions'],reference['compiler_actions']))
    pairs+=1
    held_totals=collections.Counter()
    for row in e['held_out']:
        assert row['returncode']==0
        for suffix in ('stdout','stderr'): assert sha((raw/(row['label']+'.'+suffix)).read_bytes())==row[suffix+'_sha256']
        assert sha((raw/(row['label']+'.o')).read_bytes())==row['object_sha256']
        if 'metrics' in row:
            values=struct.unpack('<12Q',(raw/(row['label']+'.metrics')).read_bytes())
            assert list(values)==row['metrics'] and values[6]==values[7]==0
            held_totals.update(dict(zip(names,values)))
    reference=next(r for r in e['held_out'] if r['variant']=='original')
    assert all(all(r[k]==reference[k] for k in ('returncode','stdout_sha256','stderr_sha256','object_sha256')) for r in e['held_out'])
    medians={name:dict(cpu=statistics.median(p['cpu'] for p in rows),wall=statistics.median(p['wall'] for p in rows)) for name,rows in costs.items()}
    audit=dict(manifest_sha256=sha((root/'evidence.json').read_bytes()), archive_sha256=sha((root/'raw.tar.gz').read_bytes()),
        auditor_sha256=sha(Path(__file__).read_bytes()), frozen_sources=len(m['source_sha256']), archive_members=len(members),
        native_compiler_actions=compiler_actions+7, separately_counted_driver_plans=plans+1,
        configure_probe_compiler_actions_not_counted=True, auditor_compiler_actions=0,
        complete_zlib_workflows=len(e['rows']), complete_zlib_comparison_pairs=pairs, held_out_comparison_pairs=6,
        real_file_roundtrips=3*len(e['rows']), zlib_metrics=dict(totals), held_out_metrics=dict(held_totals),
        native_shadow_answers_checked=totals['shadow_checks']+held_totals['shadow_checks'],
        packets=packets, scalar_packet_answers=answers,
        native_opcode_load=codes['LOAD'], packet_root_opcodes=dict(shapes), build_medians_seconds=medians,
        build_observations=costs, independent_disassembly_sha256=sha(disassembly),
        complete_closure_certified=False, adaptive_noninterference_proved=False, substantial_novelty_established=False,
        scope='Actual byte/control, native binding, source-derived scalar answer and finite complete-cost audit. Configure probes, image/setup/producer transfer/storage and wider resource/error observers are not a complete amortized accounting; the histogram and formula checks are not a native semantic certificate.')
    (root/'independent-knownbits-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
    print(json.dumps({k:audit[k] for k in ('native_compiler_actions','complete_zlib_workflows','scalar_packet_answers','build_medians_seconds')}))

if __name__=='__main__':main(Path(sys.argv[1]))
