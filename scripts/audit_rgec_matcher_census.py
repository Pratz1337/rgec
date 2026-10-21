"""Recount authentic private matcher records and inspect actual native bindings."""
import collections
import hashlib
import json
from pathlib import Path
import random
import re
import struct
import subprocess
import sys
import tarfile


def sha(data): return hashlib.sha256(data).hexdigest()
def read_json(path): return json.loads(path.read_text())


def main(root):
    m = read_json(root / 'evidence.json'); raw = root / 'raw'
    assert m['sandbox']['returncode'] == m['sandbox']['cleanup_returncode'] == 0
    for path, expected in m['source_sha256'].items(): assert sha((root / Path(path).name).read_bytes()) == expected
    assert sha((root / 'native-census-build.py').read_bytes()) == m['build_sha256']
    assert sha((root / 'matcher-census-config.json').read_bytes()) == m['config_sha256']
    result = read_json(root / 'durable-result.json'); assert result['returncode'] == 0
    assert result['raw.tar.gz_sha256'] == m['sandbox']['raw_archive_sha256']
    for name in ('raw.tar.gz', 'stdout', 'stderr'): assert sha((root / name).read_bytes()) == result[name + '_sha256']
    with tarfile.open(str(root / 'raw.tar.gz')) as archive:
        members = archive.getmembers(); assert len({v.name for v in members}) == len(members)
        for member in members:
            assert member.isfile() and member.name == 'raw/' + Path(member.name).name
            assert archive.extractfile(member).read() == (root / member.name).read_bytes()
    e = read_json(raw / 'evidence.json'); config = read_json(root / 'matcher-census-config.json')
    assert e['suite_complete'] and len(e['rows']) == 12 and len(e['plans']) == 3
    assert e['tool_sha256']['/usr/local/bin/clang'] == config['native_sha256']
    assert e['tool_sha256']['/clang_matcher_census.cpp'] == config['census_source_sha256']
    assert sha((raw / 'matcher-census-binding.json').read_bytes()) == e['binding_sha256']
    binding = read_json(raw / 'matcher-census-binding.json')
    binary = Path('/rgec-matcher-census').read_bytes()
    assert sha(binary) == e['tool_sha256']['/rgec-matcher-census'] == binding['patched_sha256']
    select = binding['select_address']; end = select + binding['select_size']; symbols = collections.Counter()
    for change in binding['changes']:
        offset = change['file_offset']; pc = change['pc']; before = bytes.fromhex(change['original_hex']); after = bytes.fromhex(change['patched_hex'])
        assert select <= pc and pc + 5 <= end and len(before) == len(after) == 5
        assert before[0] == after[0] == 0xe8
        assert pc + 5 + struct.unpack('<i', before[1:])[0] == change['old_target']
        assert pc + 5 + struct.unpack('<i', after[1:])[0] == change['new_target']
        assert binary[offset:offset + 5] == after and change['old_target'] != change['new_target']
        symbols[change['symbol']] += 1
    assert len(binding['changes']) == 4 and sorted(symbols.values()) == [2, 2]
    command = ['/usr/bin/objdump', '-d', '--start-address=%d' % select, '--stop-address=%d' % end, '/rgec-matcher-census']
    disassembly = subprocess.check_output(command)
    (root / 'independent-native-bindings.stdout').write_bytes(disassembly)
    for change in binding['changes']:
        line, = [s for s in disassembly.decode().splitlines() if s.lstrip().startswith('%x:' % change['pc'])]
        assert re.search(r'\bcallq\s+%x\s' % change['new_target'], line) and '<' + change['symbol'] + '>' in line
    indexed = {(r['source'], r['block'], r['mode']): r for r in e['rows']}; assert len(indexed) == 12
    rng = random.Random(e['seed']); counts = collections.Counter(); paths = collections.Counter(); rows = []; pairs = 0
    for source in e['sources']:
        name = Path(source['path']).name
        assert sha((raw / (name + '.original')).read_bytes()) == source['sha256']
        for block in range(2):
            order = ['native', 'census']; rng.shuffle(order)
            native = indexed[(name, block, 'native')]; census = indexed[(name, block, 'census')]
            assert native['argv'][0:2] == ['/usr/local/bin/clang', '-cc1'] and census['argv'][0] == '/rgec-matcher-census'
            assert native['argv'][1:] == census['argv'][1:]
            for mode in order:
                row = indexed[(name, block, mode)]; assert row['order'] == order.index(mode) and row['returncode'] == 0
                for suffix in ('stdout', 'stderr'): assert sha((raw / (row['label'] + '.' + suffix)).read_bytes()) == row[suffix + '_sha256']
                assert sha((raw / (row['label'] + '.o')).read_bytes()) == row['object_sha256']
            assert all(native[k] == census[k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256', 'object_sha256')); pairs += 1
            data = (raw / (census['label'] + '.census')).read_bytes()
            assert sha(data) == census['census_sha256'] and len(data) % 80 == 0
            local = collections.Counter(); branches = collections.Counter(); fast = 0
            for cursor in range(0, len(data), 80):
                v = struct.unpack_from('<10Q', data, cursor); assert v[0] == 0x524745434d435331 and v[1] in (0, 1, 2)
                local[str(v[1])] += 1
                if v[1]:
                    assert v[7] in range(4) and v[8] in (0, 1)
                    if v[7] != 3:
                        assert 1 <= v[3] <= 64 and v[3] == v[4]
                        assert v[6] == v[9] & ((1 << v[3]) - 1)
                        branch = 0 if v[5] == v[6] else 1 if v[5] & ~v[6] else 2
                        assert branch == v[7]
                        if branch < 2: assert bool(v[8]) == (branch == 0); fast += 1
                    branches['%d:%d' % (v[1], v[7])] += 1
            assert local == census['invocations'] and branches == census['mask_paths'] and fast == census['fast_classifications_checked']
            assert local['0'] > 0
            counts.update(local); paths.update(branches)
            rows.append(dict(source=name, block=block, invocations=dict(local), mask_paths=dict(branches), fast_classifications_checked=fast))
    for plan in e['plans']:
        assert plan['returncode'] == 0 and plan['argv'][-1] == '-###'
        for suffix in ('stdout', 'stderr'): assert sha((raw / (plan['label'] + '.' + suffix)).read_bytes()) == plan[suffix + '_sha256']
    audit = dict(manifest_sha256=sha((root / 'evidence.json').read_bytes()), auditor_sha256=sha(Path(__file__).read_bytes()),
        archive_sha256=sha((root / 'raw.tar.gz').read_bytes()), frozen_sources=len(m['source_sha256']), archive_members=len(members),
        native_compiler_actions=12, separately_counted_driver_plans=3, auditor_compiler_actions=0,
        literal_status_stream_object_pairs=pairs, invocation_totals=dict(counts), mask_path_totals=dict(paths), rows=rows,
        native_binding_changes=4, independent_disassembly_sha256=sha(disassembly),
        complete_closure_certified=False, substantial_novelty_established=False,
        scope='Finite invocation, native call-binding and byte/control audit. Every native predicate runs. It does not prove a complete dependency projection, cache correctness, performance gain or noninterference.')
    (root / 'independent-matcher-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
    print(json.dumps({k: audit[k] for k in ('native_compiler_actions', 'literal_status_stream_object_pairs', 'invocation_totals', 'mask_path_totals')}))


if __name__ == '__main__': main(Path(sys.argv[1]))
