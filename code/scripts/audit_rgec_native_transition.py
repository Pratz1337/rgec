"""Independent data-only reconciliation of real native captures and model results."""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile


def sha(data): return hashlib.sha256(data).hexdigest()
def load(path): return json.loads(path.read_text())


def main(root):
    manifest=load(root/'evidence.json'); result=load(root/'result.json'); raw=root/'raw'
    assert manifest['capture']['returncode']==manifest['capture']['cleanup_returncode']==result['returncode']==0
    assert manifest['native_model']['returncode']==manifest['native_model']['cleanup_returncode']==0
    for path,digest in manifest['source_sha256'].items():assert sha((root/Path(path).name).read_bytes())==digest
    for path,digest in manifest['generated_sha256'].items():assert sha((root/path).read_bytes())==digest
    for name in ('raw.tar.gz','stdout','stderr'):assert sha((root/name).read_bytes())==result[name+'_sha256']
    with tarfile.open(str(root/'raw.tar.gz')) as archive:
        members=archive.getmembers();assert len({m.name for m in members})==len(members)
        for member in members:
            parts=Path(member.name).parts;assert member.isfile() and parts[0]=='raw' and '..' not in parts
            assert archive.extractfile(member).read()==(root/member.name).read_bytes()
    e=load(raw/'evidence.json');assert e['suite_complete'] and len(e['rows'])==len(e['held_out'])==3
    config=load(root/'knownbits-scope-config.json')
    assert e['tool_sha256']['/usr/local/bin/clang']==config['native_sha256']
    for tool in ('clang_native_entry_capture.cpp',):
        assert sha((root/tool).read_bytes())==e['tool_sha256']['/'+tool]
    binding=load(raw/'native-bindings.json')
    assert sha((raw/'native-bindings.json').read_bytes())==e['native_bindings_sha256']
    original=(raw/'native-proof.elf').read_bytes()
    assert sha(original)==e['tool_sha256']['/rgec-native-entry-proof']==binding['unpatched_sha256']
    change,=binding['changes'];pos=change['file_offset'];pc=change['pc']
    before=bytes.fromhex(change['original_hex']);after=bytes.fromhex(change['patched_hex'])
    assert len(before)==len(after)==5 and before[0]==after[0]==0xe8 and original[pos:pos+5]==before
    assert pc+5+struct.unpack('<i',before[1:])[0]==change['old_target']
    assert pc+5+struct.unpack('<i',after[1:])[0]==change['new_target']
    patched=original[:pos]+after+original[pos+5:]
    assert sha(patched)==e['tool_sha256']['/rgec-knownbits-scope']==binding['patched_sha256']
    for region in binding['regions']:
        assert sha(patched[region['file_offset']:region['file_offset']+region['size']])==region['sha256']
    entry=binding['regions'][1]
    disassembly=subprocess.check_output(['/usr/bin/objdump','-d','--start-address=%d'%entry['address'],
        '--stop-address=%d'%(entry['address']+entry['size']),str(raw/'native-proof.elf')])
    line,=[line for line in disassembly.decode().splitlines() if line.lstrip().startswith('%x:'%pc)]
    assert re.search(r'\bcallq?\s+%x\s'%change['old_target'],line)
    (root/'independent-native-bindings.stdout').write_bytes(disassembly)
    counts=plans=0
    for row in e['rows']:
        actions=[json.loads(line) for line in (raw/row['label']/'actions.jsonl').read_text().splitlines()]
        assert actions==row['compiler_actions'] and len(actions)==23 and sum(a['plan'] is not None for a in actions)==19
        counts+=len(actions);plans+=19
        for action in actions:
            assert action['returncode']==0
            for suffix in ('stdout','stderr'):
                assert sha((raw/row['label']/(action['label']+'.'+suffix)).read_bytes())==action[suffix+'_sha256']
                if action['plan']:assert sha((raw/row['label']/(action['label']+'.plan.'+suffix)).read_bytes())==action['plan'][suffix+'_sha256']
        for name,value in row['artifacts'].items():
            body=(raw/(row['label']+'-artifact-'+name.replace('/','__'))).read_bytes()
            assert len(body)==value['bytes'] and sha(body)==value['sha256']
        phases=[row['configure'],row['build'],row['tests']]+[p[k] for p in row['roundtrips'] for k in ('encode','decode')]
        for phase in phases:
            assert phase['returncode']==0
            for suffix in ('stdout','stderr'):assert sha((raw/(phase['label']+'.'+suffix)).read_bytes())==phase[suffix+'_sha256']
    reference=e['rows'][0]
    for row in e['rows'][1:]:
        assert row['artifacts']==reference['artifacts']
        assert all(all(a[k]==b[k] for k in ('returncode','stdout_sha256','stderr_sha256'))
                   for a,b in zip(row['compiler_actions'],reference['compiler_actions']))
        assert all(row['tests'][k]==reference['tests'][k] for k in ('returncode','stdout_sha256','stderr_sha256'))
        assert len(row['roundtrips'])==3 and all(all(a[k]==b[k] for k in
            ('input_sha256','decoded_sha256','compressed_sha256','compressed_bytes'))
            for a,b in zip(row['roundtrips'],reference['roundtrips']))
    for row in e['held_out']:
        counts+=1
        assert row['returncode']==0 and sha((raw/(row['label']+'.o')).read_bytes())==row['object_sha256']
        for suffix in ('stdout','stderr'):assert sha((raw/(row['label']+'.'+suffix)).read_bytes())==row[suffix+'_sha256']
        assert all(row[k]==e['held_out'][0][k] for k in ('returncode','stdout_sha256','stderr_sha256','object_sha256'))
    assert len(e['plans'])==1;plans+=1
    for plan in e['plans']:
        for suffix in ('stdout','stderr'):assert sha((raw/(plan['label']+'.'+suffix)).read_bytes())==plan[suffix+'_sha256']
    check_path=root/'native-transition-check.json';check=load(check_path)
    assert sha(check_path.read_bytes())==manifest['native_model']['check_sha256']
    assert check['binary_sha256']==sha(original) and check['tool_versions']['angr']=='9.2.223'
    assert len(e['native_entries'])==len(check['rows']) and len({r['snapshot'] for r in check['rows']})==len(check['rows'])
    opcode_header=(raw/'installed-llvm__CodeGen__ISDOpcodes.h').read_text()
    fields=re.sub(r'/\*.*?\*/|//[^\n]*','',opcode_header,flags=re.S).split('enum NodeType {',1)[1].split('};',1)[0]
    codes={};value=-1
    for field in fields.split(','):
        if not field.strip():continue
        match=re.fullmatch(r'(\w+)(?:\s*=\s*(-?\d+))?',field.strip());assert match,field
        name,explicit=match.groups();value=int(explicit) if explicit else value+1;codes[name]=value
    family=config.get('capture_family','TRUNCATE32')
    assert family in ('TRUNCATE32','ADD64(SRL,Constant)')
    tls_events=0
    for capture in e['native_entries']:
        path=raw/capture['path'];meta=load(path)
        expected_opcode,expected_width=(codes['ADD'],64) if family=='ADD64(SRL,Constant)' else (codes['TRUNCATE'],32)
        assert capture['args']==meta['args'] and capture['opcode']==meta['opcode']==expected_opcode and meta['width']==expected_width and meta['args'][5]==0
        if family=='ADD64(SRL,Constant)':assert meta['child_opcode']==codes['SRL']
        assert len(meta['args'])==6 and meta['known_size']==32
        for suffix,digest in capture['files'].items():assert sha(Path(str(path)+suffix).read_bytes())==digest
        memory=Path(str(path)+'.memory').read_bytes();maps=[]
        for line in Path(str(path)+'.maps').read_text().splitlines():
            start,stop,offset,permissions=line.split();start,stop,offset=int(start,16),int(stop,16),int(offset)
            assert permissions[:2]=='rw' and stop>start and offset+stop-start<=len(memory)
            maps.append((start,stop,offset))
        known=meta['args'][3];start,stop,offset=next(m for m in maps if m[0]<=known and known+32<=m[1])
        assert memory[offset+known-start:offset+known-start+32].hex()==meta['known_before_hex']
        model,= [r for r in check['rows'] if r['snapshot']==path.name]
        assert model['metadata']==meta and model['captured_output_hex']==Path(str(path)+'.after').read_bytes().hex()
        tls=meta['fs_base']+40
        start,stop,offset=next(m for m in maps if m[0]<=tls and tls+8<=m[1])
        canary=memory[offset+tls-start:offset+tls-start+8].hex()
        tls_reads=[r for r in model['external_reads'] if r['address']==tls]
        assert tls_reads and all(r['size']==8 and r['hex']==canary for r in tls_reads)
        tls_events+=len(tls_reads)
        assert model['native_fs_bound'] and model['uncaptured_gs_symbolic']==(meta['gs_base'] is None)
        assert (meta['gs_base'] is None)==(meta['gs_capture_status']!=0)==(meta['gs_capture_errno']!=0)
        assert not model['universal_native_certificate'] and not model['relocation_certificate'] and not model['exceptional_resource_equivalence']
        if model['checked']:
            assert model['output_hex']==model['captured_output_hex'] and model['rejection'] is None
        else:assert model['rejection']
        for block in model['blocks']:
            # Bind every claimed VEX block back to a file-backed executable ELF segment.
            h=struct.unpack_from('<HHIQQQIHHHHHH',original,16);owners=[]
            for i in range(h[9]):
                kind,flags,off,address,_,filesize,_,_=struct.unpack_from('<II6Q',original,h[4]+56*i)
                if kind==1 and flags&1 and address<=block['address'] and block['address']+block['size']<=address+filesize:
                    owners.append(off+block['address']-address)
            file_offset,=owners;assert sha(original[file_offset:file_offset+block['size']])==block['sha256']
    delivered=dict(manifest_sha256=sha((root/'evidence.json').read_bytes()),archive_sha256=sha((root/'raw.tar.gz').read_bytes()),
        auditor_sha256=sha(Path(__file__).read_bytes()),archive_members=len(members),native_compiler_actions=counts,
        separately_counted_driver_plans=plans,complete_zlib_workflows=3,upstream_tests_passed=3,real_file_roundtrips=9,
        complete_workflow_comparison_pairs=2,held_out_cpp_comparison_pairs=2,
        native_entry_snapshots=len(e['native_entries']),model_transition_witnesses=sum(r['checked'] for r in check['rows']),
        captured_native_fs_bases_verified=True,native_tls_read_events=tls_events,capture_family=family,
        symbolic_uncaptured_gs_entries=sum(r['metadata']['gs_base'] is None for r in check['rows']),
        native_model_check_sha256=sha(check_path.read_bytes()),native_model_rejections=[r['rejection'] for r in check['rows'] if not r['checked']],
        independent_disassembly_sha256=sha(disassembly),auditor_compiler_actions=0,
        universal_native_certificate=False,relocation_certificate=False,adaptive_noninterference_proved=False,
        substantial_novelty_established=False,scope='Byte and control audit; no symbolic rerun, ISA proof, generic footprint proof or speedup claim.')
    output_name='independent-native-transition-audit.json'
    if (root/'native-contract.json').exists():
        cm=load(root/'contract-evidence.json');cr=load(root/'contract-result.json');cc=load(root/'contract-config.json')
        contract=load(root/'native-contract.json')
        assert cm['worker']['returncode']==cm['worker']['cleanup_returncode']==cr['returncode']==0
        for name,digest in cm['frozen_sha256'].items():assert sha((root/('contract-'+name)).read_bytes())==digest
        assert cc['archive_sha256']==sha((root/'raw.tar.gz').read_bytes())
        assert cc['witness_sha256']==sha(check_path.read_bytes())
        assert cc['checker_sha256']==contract['source_sha256']==sha((root/'contract-derive_rgec_native_contract.py').read_bytes())
        digest=sha((root/'native-contract.json').read_bytes())
        assert digest==cm['worker']['contract_sha256']==cr['contract_sha256']
        assert contract['binary_sha256']==cc['proof_elf_sha256']==sha(original)
        assert contract['tool_versions']==check['tool_versions'] and len(contract['rows'])==len(check['rows'])==4
        for row in contract['rows']:
            witness,=[r for r in check['rows'] if r['snapshot']==row['snapshot']]
            capture,=[r for r in e['native_entries'] if Path(r['path']).name==row['snapshot']]
            path=raw/capture['path'];memory=Path(str(path)+'.memory').read_bytes();maps=[]
            for line in Path(str(path)+'.maps').read_text().splitlines():
                lo,hi,off,_=line.split();maps.append((int(lo,16),int(hi,16),int(off)))
            def captured_bytes(address,size):
                lo,hi,off=next(m for m in maps if m[0]<=address and address+size<=m[1])
                return memory[off+address-lo:off+address-lo+size]
            assert row['model_contract_checked'] and row['rejection'] is None and row['code_blocks']==witness['blocks']
            assert row['native_nonstack_reads_checked']==len(witness['external_reads'])==37
            assert row['native_writes_checked']==len(witness['writes'])==134 and row['smt_inequality_checks']==182
            objects={o['name']:o for o in row['object_templates']}
            assert len(objects)==8 and sum(o['bytes'] for o in objects.values())==232
            args=witness['metadata']['args']
            assert objects['node']['actual_base']==args[1] and objects['known']['actual_base']==args[3]
            assert objects['demand']['actual_base']==args[4] and objects['thread_canary']['actual_base']==witness['metadata']['fs_base']+40
            assert len(row['pointer_edges'])==4
            for edge in row['pointer_edges']:
                address=objects[edge['source']]['actual_base']+edge['offset']
                assert int.from_bytes(captured_bytes(address,8),'little')==objects[edge['target']]['actual_base']
            assert sum(len(b) for b in row['fixed_object_bytes'].values())==38
            for name,values in row['fixed_object_bytes'].items():
                for offset,value in values.items():assert captured_bytes(objects[name]['actual_base']+int(offset),1)[0]==value
            assert len(row['fixed_global_bytes'])==24
            for address,value in row['fixed_global_bytes'].items():
                address=int(address);owners=[]
                for i in range(h[9]):
                    kind,flags,off,base,_,filesize,_,_=struct.unpack_from('<II6Q',original,h[4]+56*i)
                    if kind==1 and flags&4 and not flags&2 and base<=address<base+filesize:owners.append(off+address-base)
                off,=owners;assert original[off]==value
            assert not row['universal_native_certificate'] and not row['runtime_admission_implemented'] and not row['exceptional_resource_equivalence']
        delivered.update(conditional_contracts_byte_audited=4,conditional_contract_sha256=digest,
            conditional_contract_manifest_sha256=sha((root/'contract-evidence.json').read_bytes()),
            independently_reran_symbolic_model=False,symbolic_claims_proved_by_this_auditor=False)
        output_name='independent-native-contract-audit.json'
    (root/output_name).write_text(json.dumps(delivered,indent=2)+'\n')
    print(json.dumps(delivered,indent=2))


if __name__=='__main__':main(Path(sys.argv[1]))
