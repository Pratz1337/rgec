"""Check actual native entry snapshots in a strict VEX execution model on Modal.

This emits finite transition witnesses, not an ISA proof or a cross-heap cache.
Unknown mappings, symbolic addresses, effects, hooks and unsupported instructions
reject the candidate. No library SimProcedure supplies an assumed return value.
"""
import hashlib
import json
import logging
from pathlib import Path
import time

import angr
import claripy

SYMBOL = '_ZNK4llvm12SelectionDAG16computeKnownBitsENS_7SDValueERNS_9KnownBitsERKNS_5APIntEj'
STACK = 0x600000000000
RETURN = 0x610000000000
PRESERVED = ('rbx', 'rbp', 'r12', 'r13', 'r14', 'r15')


class Rejected(Exception):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(binary, snapshot):
    started = time.monotonic()
    meta = json.loads(snapshot.read_text())
    mappings = [tuple(int(x, 16) if i < 2 else int(x) if i == 2 else x
                      for i, x in enumerate(line.split()))
                for line in snapshot.with_suffix(snapshot.suffix + '.maps').read_text().splitlines()]
    memory = snapshot.with_suffix(snapshot.suffix + '.memory').read_bytes()
    expected = snapshot.with_suffix(snapshot.suffix + '.after').read_bytes()
    for start, stop, offset, permissions in mappings:
        assert stop > start and offset + stop - start <= len(memory) and permissions[:2] == 'rw'
        assert stop <= STACK - 0x100000 or start >= STACK + 0x100000
    args = meta['args']
    known, size = args[3], meta['known_size']
    assert size == 32 and len(expected) == size
    project = angr.Project(str(binary), auto_load_libs=False, use_sim_procedures=False)
    symbol = project.loader.main_object.get_symbol(SYMBOL)
    assert symbol is not None
    # ABI arguments and the captured real memory initialize the model. Scratch
    # registers and untouched stack cells stay symbolic. The private model stack
    # does not stand in for any captured recipient object.
    state = project.factory.call_state(symbol.rebased_addr, *args,
        prototype='void f(void *, void *, unsigned int, void *, void *, unsigned int)',
        stack_base=STACK, ret_addr=RETURN)
    # Loader-created TLS is not the captured native thread. Bind its segment
    # bases explicitly so stack-protector reads use genuine captured bytes.
    state.regs.fs = meta['fs_base']
    state.regs.gs = (meta['gs_base'] if meta['gs_base'] is not None else
                    claripy.BVS('uncaptured_native_gs', 64, explicit_name=True))
    assert any(start <= meta['fs_base'] + 40 and meta['fs_base'] + 48 <= stop
               for start, stop, _, _ in mappings)
    initial_sp = state.solver.eval(state.regs.rsp)
    saved = {r: getattr(state.regs, r) for r in PRESERVED + ('fs', 'gs')}
    initialized = set(range(initial_sp, initial_sp + 8))
    reads, writes, blocks, native_calls = [], [], [], []
    loaded = set()

    def attributes(s):
        return getattr(s.inspect, 'attrs', s.inspect)

    def concrete(s, value, label):
        if isinstance(value, int): return value
        values = s.solver.eval_upto(value, 2)
        if len(values) != 1: raise Rejected('nonunique ' + label)
        return values[0]

    def materialize(s, address, length):
        for cell in range(address, address + length):
            if cell in loaded or cell in initialized: continue
            if STACK - 0x100000 <= cell < STACK:
                raise Rejected('read of unwritten private stack at %#x' % cell)
            owners = [m for m in mappings if m[0] <= cell < m[1]]
            if len(owners) == 1:
                start, _, offset, _ = owners[0]
                body = memory[offset + cell - start:offset + cell - start + 1]
            else:
                segment = project.loader.main_object.find_segment_containing(cell)
                if segment is None or segment.is_writable or not segment.is_readable:
                    raise Rejected('uncaptured native read at %#x' % cell)
                body = project.loader.memory.load(cell, 1)
            s.memory.store(cell, body, inspect=False, disable_actions=True)
            loaded.add(cell)

    def on_read(s):
        a = attributes(s)
        address = concrete(s, a.mem_read_address, 'read address')
        length = concrete(s, a.mem_read_length, 'read length')
        if not 0 < length <= 64: raise Rejected('unsupported read size')
        materialize(s, address, length)
        if not STACK - 0x100000 <= address < STACK + 8:
            body = s.memory.load(address, length, inspect=False, disable_actions=True)
            if s.solver.symbolic(body): raise Rejected('unresolved native input')
            reads.append(dict(pc=concrete(s, s.regs.rip, 'read pc'), address=address,
                              size=length, hex=s.solver.eval(body, cast_to=bytes).hex()))

    def on_write(s):
        a = attributes(s)
        address = concrete(s, a.mem_write_address, 'write address')
        length = concrete(s, a.mem_write_length, 'write length')
        local = STACK - 0x100000 <= address and address + length <= initial_sp
        output = known <= address and address + length <= known + size
        if not (local or output): raise Rejected('unconfined native write at %#x' % address)
        initialized.update(range(address, address + length))
        writes.append(dict(pc=concrete(s, s.regs.rip, 'write pc'), address=address,
                           size=length, kind='private-stack' if local else 'KnownBits'))

    def reject_event(s):
        raise Rejected('unsupported effect/model event at %#x' % concrete(s, s.regs.rip, 'event pc'))

    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=on_read)
    state.inspect.b('mem_write', when=angr.BP_BEFORE, action=on_write)
    for event in ('simprocedure', 'syscall', 'dirty'):
        state.inspect.b(event, when=angr.BP_BEFORE, action=reject_event)
    reason = None
    result = None
    try:
        for _ in range(20000):
            pc = concrete(state, state.regs.rip, 'instruction address')
            if pc == RETURN: break
            owner = project.loader.find_object_containing(pc)
            segment = project.loader.main_object.find_segment_containing(pc)
            if owner is not project.loader.main_object or segment is None or not segment.is_executable:
                raise Rejected('call/exit outside pinned native ELF at %#x' % pc)
            if project.is_hooked(pc): raise Rejected('hooked native instruction at %#x' % pc)
            block = project.factory.block(pc)
            blocks.append(dict(address=pc, size=block.size, sha256=sha(block.bytes)))
            successors = project.factory.successors(state)
            live = [s for s in successors.flat_successors if s.solver.satisfiable()]
            if successors.unconstrained_successors or len(live) != 1:
                raise Rejected('unresolved native control/exit')
            state = live[0]
            if state.history.jumpkind == 'Ijk_Call':
                native_calls.append(concrete(state, state.regs.rip, 'call target'))
        else: raise Rejected('native path exceeds construction bound')
        if state.solver.eval(state.regs.rsp) != initial_sp + 8:
            raise Rejected('native stack/return mismatch')
        for register, value in saved.items():
            if state.solver.satisfiable(extra_constraints=[getattr(state.regs, register) != value]):
                raise Rejected('ABI live-out mismatch: ' + register)
        materialize(state, known, size)
        value = state.memory.load(known, size, inspect=False, disable_actions=True)
        if state.solver.symbolic(value): raise Rejected('symbolic native live-out')
        result = state.solver.eval(value, cast_to=bytes)
        if result != expected: raise Rejected('native answer disagrees with captured execution')
    except (Rejected, angr.errors.AngrError, claripy.errors.ClaripyError) as error:
        reason = '%s: %s' % (type(error).__name__, error)
    return dict(snapshot=snapshot.name, entry=symbol.rebased_addr,
        metadata=meta, checked=reason is None, rejection=reason,
        native_fs_bound=True, uncaptured_gs_symbolic=meta['gs_base'] is None,
        output_hex=None if result is None else result.hex(), captured_output_hex=expected.hex(),
        external_reads=reads, writes=writes, blocks=blocks, native_calls=native_calls,
        wall_seconds=time.monotonic()-started, model='angr/VEX; no external SimProcedures',
        universal_native_certificate=False, relocation_certificate=False,
        exceptional_resource_equivalence=False, substantial_novelty_established=False)


if __name__ == '__main__':
    import sys
    logging.getLogger('angr').setLevel(logging.ERROR)
    logging.getLogger('cle').setLevel(logging.ERROR)
    binary, folder, output = map(Path, sys.argv[1:])
    rows = []
    for snapshot in sorted(folder.rglob('*.entry')):
        rows.append(check(binary, snapshot))
        output.write_text(json.dumps(dict(binary_sha256=sha(binary.read_bytes()),
            tool_versions={p: __import__(p).__version__ for p in ('angr','claripy','pyvex')},
            rows=rows, transition_witnesses=sum(r['checked'] for r in rows),
            universal_native_certificate=False, substantial_novelty_established=False), indent=2)+'\n')
        print(snapshot.name, rows[-1]['checked'], rows[-1]['rejection'], flush=True)
    assert rows, 'No genuine native entry snapshots were supplied'
