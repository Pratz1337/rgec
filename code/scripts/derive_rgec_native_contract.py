"""Address-parametric VEX contract construction from genuine checked entries.

Object readability/ownership and immutable code are explicit model premises.
Address substitution is allowed only after SMT proves the logical access equals
the declared object plus offset. Every native block/read/write must be accounted
for. This is a conditional instruction-model result, not native ISA verification.
"""
import hashlib
import json
import logging
from pathlib import Path
import sys
import time

import angr
import claripy

SYMBOL = '_ZNK4llvm12SelectionDAG16computeKnownBitsENS_7SDValueERNS_9KnownBitsERKNS_5APIntEj'
STACK = 0x600000000000
RETURN = 0x610000000000
PRESERVED = ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15')


class Rejected(Exception):
    pass


def sha(data): return hashlib.sha256(data).hexdigest()


def derive(binary, snapshot, witness):
    start_time=time.monotonic(); meta=json.loads(snapshot.read_text()); args=meta['args']
    assert witness['checked'] and witness['metadata']==meta
    arithmetic=meta['opcode']==52
    assert (meta['opcode'],meta['width']) in ((146,32),(52,64))
    maps=[]
    for line in Path(str(snapshot)+'.maps').read_text().splitlines():
        lo,hi,offset,perms=line.split();maps.append((int(lo,16),int(hi,16),int(offset)))
    memory=Path(str(snapshot)+'.memory').read_bytes()
    project=angr.Project(str(binary),auto_load_libs=False,use_sim_procedures=False)
    symbol=project.loader.main_object.get_symbol(SYMBOL);assert symbol
    tls=meta['fs_base']+40
    roots={args[1]:'node',args[3]:'known',args[4]:'demand',tls:'thread_canary'}
    links={};reads=witness['external_reads']

    def captured(address):
        matches=[m for m in maps if m[0]<=address<m[1]]
        assert len(matches)==1, 'Uncaptured template byte'
        lo,_,offset=matches[0];return memory[offset+address-lo]

    def owner(address):
        matches=[p for p in roots if p<=address<p+128]
        return max(matches) if matches else None

    # Infer pointer edges only from actual eight-byte reads whose values lead
    # to later captured reads. Object identities, including aliases, are retained.
    for i,event in enumerate(reads):
        if event['size']!=8:continue
        value=int.from_bytes(bytes.fromhex(event['hex']),'little')
        if not any(lo<=value<hi for lo,hi,_ in maps):continue
        if not any(value<=later['address']<value+128 for later in reads[i+1:]):continue
        source=owner(event['address'])
        if source is None:raise Rejected('pointer edge outside inferred objects')
        offset=event['address']-source
        if value not in roots:roots[value]=roots[source]+'/p%d'%offset
        links[(source,offset)]=value
    extents={p:0 for p in roots};extents[args[3]]=32;extents[tls]=8
    for event in reads:
        p=owner(event['address'])
        if p is not None:extents[p]=max(extents[p],event['address']+event['size']-p)
    for p in extents:extents[p]=(extents[p]+7)//8*8
    assert all(0<size<=128 for size in extents.values())
    ordered=sorted(roots)
    assert all(p+extents[p]<=q for p,q in zip(ordered,ordered[1:])), 'Overlapping inferred objects'
    # This initial supported family has one operand edge and two value-type edges.
    # A different graph is rejected instead of inheriting this contract.
    if not arithmetic:assert len(roots)==8 and len(links)==4
    symbols={p:claripy.BVS('object_'+roots[p].replace('/','_'),64,explicit_name=True) for p in roots}
    opaque_dag=claripy.BVS('unused_dag_argument',64,explicit_name=True)
    state=project.factory.call_state(symbol.rebased_addr,opaque_dag,symbols[args[1]],args[2],
        symbols[args[3]],symbols[args[4]],args[5],
        prototype='void f(void *, void *, unsigned int, void *, void *, unsigned int)',stack_base=STACK,ret_addr=RETURN)
    state.regs.fs=symbols[tls]-40
    state.regs.gs=meta['gs_base'] if meta['gs_base'] is not None else claripy.BVS('uncaptured_native_gs',64,explicit_name=True)
    initial_sp=state.solver.eval(state.regs.rsp);saved={r:getattr(state.regs,r) for r in PRESERVED+('fs','gs')}
    initialized=set(range(initial_sp,initial_sp+8));loaded=set()
    globals_read={};fixed_object_bytes={};queries=0;steps=[];read_count=write_count=0
    segments=list(project.loader.main_object.segments)
    for p,base in symbols.items():
        size=extents[p]
        state.add_constraints(base>=0x1000,base<=0x7fffffffffff-size,(base&7)==0,
            claripy.Or(base+size<=STACK-0x100000,base>=STACK+8))
        for segment in segments:
            state.add_constraints(claripy.Or(base+size<=segment.min_addr,base>segment.max_addr))
    for i,p in enumerate(ordered):
        for q in ordered[i+1:]:state.add_constraints(claripy.Or(symbols[p]+extents[p]<=symbols[q],symbols[q]+extents[q]<=symbols[p]))
    assert state.solver.satisfiable(), 'Unsatisfiable declared ownership domain'

    def store_field(address,value,size):
        state.memory.store(address,value,size=size,endness=project.arch.memory_endness,inspect=False,disable_actions=True)
        loaded.update(range(address,address+size))

    store_field(tls,claripy.BVS('stable_thread_canary',64,explicit_name=True),8)

    # Native output is initialized with arbitrary prior values and padding.
    # Equal APInt widths 1..64 prevent an assumed-away old wide-value free.
    old_width=claripy.BVS('prior_known_width',32,explicit_name=True)
    state.add_constraints(old_width>=1,old_width<=64)
    for offset in (0,16):store_field(args[3]+offset,claripy.BVS('prior_known_value_%d'%offset,64,explicit_name=True),8)
    for offset in (8,24):store_field(args[3]+offset,old_width,4)
    for offset in (12,28):store_field(args[3]+offset,claripy.BVS('prior_known_padding_%d'%offset,32,explicit_name=True),4)
    for (p,offset),target in links.items():store_field(p+offset,symbols[target],8)
    # Nonempty result lists suffice for ResNo zero in this native path. The
    # actual bytes locate these fields; symbolic execution checks their role.
    nodes=[p for p in roots if (p,40) in links] if arithmetic else [args[1],links[(links[(args[1],32)],0)]]
    for p in nodes:
        count=claripy.BVS('value_count_'+roots[p].replace('/','_'),16,explicit_name=True)
        state.add_constraints(count>=1);store_field(p+58,count,2)
    operands=links[(args[1],32)]
    if arithmetic:
        arrays={links[(p,32)] for p in nodes if (p,32) in links}
        for (p,offset),target in links.items():
            if p in arrays:
                store_field(p+offset+12,claripy.BVS('operand_padding_'+roots[p].replace('/','_')+'_'+str(offset),32,explicit_name=True),4)
        # Manually selected ADD64(SRL(..., Constant8), Constant64(1)) relation.
        # The native model must check the complete graph and all data/control.
        shifted=links[(operands,0)];shift_operands=links[(shifted,32)]
        shift_node=links[(shift_operands,40)];shift_object=links[(shift_node,80)]
        shift_address=shift_object+24
        assert int.from_bytes(bytes(captured(shift_node+24+i) for i in range(2)),'little')==10
        assert int.from_bytes(bytes(captured(shift_object+32+i) for i in range(4)),'little')==8
        assert int.from_bytes(bytes(captured(shift_address+i) for i in range(8)),'little')==3
        right=links[(operands,40)];right_object=links[(right,80)]
        assert int.from_bytes(bytes(captured(right+24+i) for i in range(2)),'little')==10
        assert int.from_bytes(bytes(captured(right_object+24+i) for i in range(8)),'little')==1
        assert int.from_bytes(bytes(captured(right_object+32+i) for i in range(4)),'little')==64
        shift=claripy.BVS('key_shift_amount',8,explicit_name=True)
        state.add_constraints(shift>=2,shift<=63)
        store_field(shift_address,claripy.ZeroExt(56,shift),8)
        expected_zero=claripy.BVV((1<<64)-1,64) << (claripy.BVV(65,64)-claripy.ZeroExt(56,shift))
    else:
        store_field(operands+12,claripy.BVS('operand_pair_padding',32,explicit_name=True),4)
    initial_known=[state.memory.load(args[3]+i,1,inspect=False,disable_actions=True) for i in range(32)]
    known_after=Path(str(snapshot)+'.after').read_bytes()

    def attrs(s):return getattr(s.inspect,'attrs',s.inspect)

    def integer(s,value,label):
        if isinstance(value,int):return value
        values=s.solver.eval_upto(value,2)
        if len(values)!=1:raise Rejected('nonunique '+label)
        return values[0]

    def prove_equal(s,left,right,label):
        nonlocal queries
        queries+=1
        if s.solver.satisfiable(extra_constraints=[left!=right]):raise Rejected(label)

    def logical(address):
        matches=[p for p in roots if p<=address< p+extents[p]]
        return (symbols[matches[0]]+address-matches[0]) if len(matches)==1 else claripy.BVV(address,64)

    def materialize(s,address,length):
        for cell in range(address,address+length):
            if cell in loaded or cell in initialized:continue
            if STACK-0x100000<=cell<STACK:raise Rejected('unwritten private stack')
            p=owner(cell)
            segment=project.loader.main_object.find_segment_containing(cell)
            if p is not None and cell<p+extents[p]:
                value=captured(cell);fixed_object_bytes.setdefault(roots[p],{})[str(cell-p)]=value
            elif segment is not None and segment.is_readable:
                value=captured(cell) if segment.is_writable else project.loader.memory.load(cell,1)[0]
                globals_read[cell]=value
            else:raise Rejected('read outside contract objects/code at %#x'%cell)
            s.memory.store(cell,bytes([value]),inspect=False,disable_actions=True);loaded.add(cell)

    def on_read(s):
        nonlocal read_count
        a=attrs(s);length=integer(s,a.mem_read_length,'read size');pc=integer(s,s.regs.rip,'read pc')
        values=s.solver.eval_upto(a.mem_read_address,2)
        if len(values)==1 and STACK-0x100000<=values[0]<STACK+8:
            address=values[0]
        else:
            if read_count==len(reads):raise Rejected('additional non-stack native read')
            event=reads[read_count];read_count+=1;address=event['address']
            if event['pc']!=pc or event['size']!=length:raise Rejected('native read path changed')
            prove_equal(s,a.mem_read_address,logical(address),'address dependence outside logical read footprint')
            a.mem_read_address=claripy.BVV(address,64)
        if not 0<length<=64:raise Rejected('unsupported read length')
        materialize(s,address,length)

    def on_write(s):
        nonlocal write_count
        a=attrs(s);length=integer(s,a.mem_write_length,'write size');pc=integer(s,s.regs.rip,'write pc')
        if write_count==len(witness['writes']):raise Rejected('additional native write')
        event=witness['writes'][write_count];write_count+=1;address=event['address']
        if event['pc']!=pc or event['size']!=length:raise Rejected('native write path changed')
        prove_equal(s,a.mem_write_address,logical(address),'address dependence outside logical write footprint')
        a.mem_write_address=claripy.BVV(address,64)
        local=STACK-0x100000<=address and address+length<=initial_sp
        output=args[3]<=address and address+length<=args[3]+32
        if not (local or output):raise Rejected('nonlocal native write')
        initialized.update(range(address,address+length))

    def reject_event(s):raise Rejected('unsupported effect/model event')
    state.inspect.b('mem_read',when=angr.BP_BEFORE,action=on_read)
    state.inspect.b('mem_write',when=angr.BP_BEFORE,action=on_write)
    for event in ('simprocedure','syscall','dirty'):state.inspect.b(event,when=angr.BP_BEFORE,action=reject_event)
    rejection=None
    try:
        for block in witness['blocks']:
            pc=integer(state,state.regs.rip,'native pc')
            if pc!=block['address'] or project.is_hooked(pc):raise Rejected('native code path changed')
            native=project.factory.block(pc)
            if sha(native.bytes)!=block['sha256']:raise Rejected('native block binding changed')
            successors=project.factory.successors(state)
            live=[s for s in successors.flat_successors if s.solver.satisfiable()]
            if successors.unconstrained_successors or len(live)!=1:raise Rejected('additional possible native branch/exit at %#x'%pc)
            state=live[0];steps.append(block)
        prove_equal(state,state.regs.rip,claripy.BVV(RETURN,64),'native return changed')
        prove_equal(state,state.regs.rsp,claripy.BVV(initial_sp+8,64),'native stack changed')
        for register,value in saved.items():prove_equal(state,getattr(state.regs,register),value,'ABI live-out changed: '+register)
        assert read_count==len(reads) and write_count==len(witness['writes'])
        expected_bytes=[claripy.BVV(known_after[i],8) if i in list(range(12))+list(range(16,28)) else initial_known[i] for i in range(32)]
        if arithmetic:
            assert known_after[:8]==bytes.fromhex('00000000000000c0') and known_after[16:24]==bytes(8)
            for i in range(8):expected_bytes[i]=claripy.Extract(8*i+7,8*i,expected_zero)
        expected=claripy.Concat(*expected_bytes)
        materialize(state,args[3],32)
        result=state.memory.load(args[3],32,inspect=False,disable_actions=True)
        prove_equal(state,result,expected,'native output depends on relocated/ignored state')
    except (Rejected,angr.errors.AngrError,claripy.errors.ClaripyError) as error:
        rejection='%s: %s'%(type(error).__name__,error)
    contract=dict(snapshot=snapshot.name,model_contract_checked=rejection is None,rejection=rejection,
        code_blocks=steps,object_templates=[dict(name=roots[p],actual_base=p,bytes=extents[p]) for p in ordered],
        pointer_edges=[dict(source=roots[p],offset=o,target=roots[t]) for (p,o),t in sorted(links.items())],
        fixed_global_bytes={str(k):v for k,v in globals_read.items()},fixed_object_bytes=fixed_object_bytes,
        smt_inequality_checks=queries,
        native_nonstack_reads_checked=read_count,native_writes_checked=write_count,
        symbolic_fields=['independently placed disjoint aligned owned objects including native TLS canary','unused DAG argument','uncaptured GS base when unavailable',
            'stable thread canary','prior KnownBits values and padding','equal prior KnownBits widths 1..64','nonempty result-list counts','operand-pair padding'],
        preconditions=['declared objects are readable, stable and owned; KnownBits writable',
            'object extents are pairwise disjoint and do not overlap code/model stack',
            'remaining scalar field bytes and pointer graph equal the template',
            'fixed globals and native code bindings match; no concurrent mutation'],
        result=None if rejection else 'Zero=UINT64_MAX<<(65-shift), One=0, width64; native output padding preserved' if arithmetic else 'Zero=0, One=0, width 32; native output padding preserved',
        wall_seconds=time.monotonic()-start_time,universal_native_certificate=False,
        exceptional_resource_equivalence=False,runtime_admission_implemented=False,substantial_novelty_established=False)
    if arithmetic:
        contract['parameter_relation']=dict(name='key_shift_amount',bits=8,minimum=2,maximum=63,
            object=roots[shift_object],offset=24,storage_bytes=8,native_captured_value=3,
            output_zero='UINT64_MAX << (65 - shift)',output_one=0,output_width=64,
            data_relation_manually_selected=True,additional_native_executions=0)
        contract['symbolic_fields'].append('key shift parameter 2..63 in captured ConstantInt APInt8 storage')
    return contract


if __name__=='__main__':
    logging.getLogger('angr').setLevel(logging.ERROR);logging.getLogger('cle').setLevel(logging.ERROR)
    binary,folder,witness_path,output=map(Path,sys.argv[1:])
    witnesses=json.loads(witness_path.read_text());rows=[]
    for snapshot in sorted(folder.rglob('*.entry')):
        witness,=[r for r in witnesses['rows'] if r['snapshot']==snapshot.name]
        rows.append(derive(binary,snapshot,witness))
        output.write_text(json.dumps(dict(binary_sha256=sha(binary.read_bytes()),source_sha256=sha(Path(__file__).read_bytes()),
            tool_versions={p:__import__(p).__version__ for p in ('angr','claripy','pyvex')},rows=rows,
            checked_model_contracts=sum(r['model_contract_checked'] for r in rows),
            universal_native_certificate=False,runtime_admission_implemented=False,substantial_novelty_established=False),indent=2)+'\n')
        print(snapshot.name,rows[-1]['model_contract_checked'],rows[-1]['rejection'],flush=True)
    assert rows
