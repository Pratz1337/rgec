"""Re-derive native scope comparison from retained bytes; no compiler execution."""
import collections
import hashlib
import json
from pathlib import Path
import re
import statistics
import sys
import tarfile

sys.dont_write_bytecode = True
root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
from backend_recipe_store import computation_key, packet_key
from rgec_backend_probe import key, queue_signature
from rgec_native_effect_probe import signature


def sha(data): return hashlib.sha256(data).hexdigest()


manifest = json.loads((root / 'evidence.json').read_text())
assert 'error' not in manifest
assert len(manifest['sandboxes']) == 3
assert all(row['returncode'] == 0 and row['cleanup_returncode'] == 137 for row in manifest['sandboxes'])
for path, digest in manifest['source_sha256'].items():
    assert sha((root / Path(path).name).read_bytes()) == digest
preload_bytes = (root / 'preload.json').read_bytes()
assert sha(preload_bytes) == manifest['preload_sha256']
preload = json.loads(preload_bytes)
prior_root = Path(manifest['prior_root'])
assert sha((prior_root / 'evidence.json').read_bytes()) == manifest['prior_manifest_sha256']
prior = json.loads((prior_root / 'evidence.json').read_text())
profiles = {item['profile']: item for item in preload['profiles']}
for item in profiles.values():
    prior_case = next(row for row in prior['comparisons'] if row['label'] ==
                     item['profile'] + '-A-prefix-ignored-separate-producer-miss')
    folder = prior_root / prior_case['actual']['request_id']
    bound = (folder / 'query.bin').read_bytes()
    packet = (folder / 'reply.packet').read_bytes()
    assert sha(bound) == item['full_context_sha256']
    assert packet == bytes.fromhex(item['delivery_hex'])
    assert packet_key(packet) == computation_key(bound)
    assert sha(packet) == item['receipt']['packet_sha256']
    assert sha(computation_key(bound)) == item['receipt']['key_sha256']
    assert item['receipt']['origin']['captured_context_sha256'] == sha(bound)
    for history in ('ignored', 'warning'):
        assert bytes.fromhex(item[history + '_source_hex']) == (prior_root /
            (item['source'] + '-prefix-' + history + '.source')).read_bytes()
    assert bytes.fromhex(item['map_hex']) == (prior_root / (item['source'] + '-A.yaml')).read_bytes()
archive_members = 0
routes = collections.Counter()
costs = collections.defaultdict(list)
native_pairs = 0
warning_history_pairs = 0
for worker in manifest['sandboxes']:
    assert worker['tool_sha256'] == manifest['tool_sha256']
    folder = root / ('worker-' + str(worker['worker']))
    assert sha((folder / 'raw.tar.gz').read_bytes()) == worker['raw_archive_sha256']
    with tarfile.open(folder / 'raw.tar.gz') as archive:
        for member in archive:
            assert member.isfile() and member.name == 'raw/' + Path(member.name).name
            assert archive.extractfile(member).read() == (folder / Path(member.name).name).read_bytes()
            archive_members += 1
    evidence = json.loads((folder / 'evidence.json').read_text())
    rows = evidence['rows']
    assert len(rows) == 36 and len(evidence['planned_order']) == len(rows)
    assert evidence['seed'] == 6421
    from random import Random
    randomizer = Random(6421)
    planned = []
    for item in preload['profiles']:
        for block in range(2):
            order = [(history, mode) for history in ('ignored', 'warning')
                     for mode in ('native', 'full-context', 'computation')]
            randomizer.shuffle(order)
            planned.extend({'profile': item['profile'], 'block': block,
                            'history': history, 'mode': mode} for history, mode in order)
    assert planned == evidence['planned_order']
    for planned_row, row in zip(planned, rows):
        assert all(row[name] == value for name, value in planned_row.items())
        item = profiles[row['profile']]; label = row['label']
        assert row['source_sha256'] == sha(bytes.fromhex(item[row['history'] + '_source_hex']))
        assert row['argv'][1:] == ['-cc1'] + item['arguments']
        for suffix in ('stdout', 'stderr', 'control'):
            assert sha((folder / (label + '.' + suffix)).read_bytes()) == row[suffix + '_sha256']
        assert sha((folder / (label + '.held')).read_bytes()) == row['held_fd_content_sha256']
        for suffix, path in zip(('output', 'alias'), row['paths']):
            assert sha((folder / (label + '.' + suffix)).read_bytes()) == row['after'][path]['content_sha256']
        reference = next(other for other in rows if other['profile'] == row['profile'] and
            other['block'] == row['block'] and other['history'] == row['history'] and other['mode'] == 'native')
        assert all(row[name] == reference[name] for name in ('returncode', 'stdout_sha256', 'stderr_sha256'))
        assert signature(row) == signature(reference)
        assert queue_signature(row['events']) == queue_signature(reference['events'])
        if row['mode'] != 'native':
            native_pairs += 1
            bound = (folder / (label + '.query')).read_bytes()
            packet = (folder / (label + '.reply')).read_bytes()
            assert sha(bound) == row['query_sha256']
            assert sha(computation_key(bound)) == row['computation_sha256'] == item['receipt']['key_sha256']
            assert sha(packet) == row['reply_sha256']
            actual_bound, receipt = key((folder / (label + '.control')).read_bytes())
            assert actual_bound == bound and receipt.decode() == row['receipt']
            scope_miss = row['mode'] == 'full-context' and sha(bound) != item['full_context_sha256']
            if scope_miss:
                assert not packet and receipt == b'RGECF1'
                assert row['store_route'] == 'scope-miss-native-computation'
            else:
                assert packet == bytes.fromhex(item['delivery_hex']) and receipt == b'RGECH1'
                assert row['store_route'] == 'authenticated-hit'
            routes[(row['mode'], row['history'], row['store_route'])] += 1
        else:
            assert not row['query_emitted']
        total_cpu = row['child_cpu_seconds'] + row['service_cpu_seconds']
        costs[(row['profile'], row['history'], row['mode'])].append((total_cpu, row['helper_wall_seconds']))
    for profile in profiles:
        for block in range(2):
            ignored = next(row for row in rows if row['profile'] == profile and row['block'] == block and
                           row['mode'] == 'native' and row['history'] == 'ignored')
            warning = next(row for row in rows if row['profile'] == profile and row['block'] == block and
                           row['mode'] == 'native' and row['history'] == 'warning')
            def warning_count(row):
                data = (folder / (row['label'] + '.stderr')).read_bytes()
                counts = re.findall(rb'(?m)^(\d+) warnings? generated\.$', data)
                assert len(counts) == 1
                return int(counts[0])
            assert warning_count(warning) == warning_count(ignored) + 2
            warning_history_pairs += 1
summary = [{'profile': profile, 'history': history, 'mode': mode,
    'observations': len(values), 'median_total_measured_cpu_seconds': statistics.median(value[0] for value in values),
    'median_helper_wall_seconds': statistics.median(value[1] for value in values)}
    for (profile, history, mode), values in sorted(costs.items())]
result = {'root': str(root), 'manifest_sha256': sha((root / 'evidence.json').read_bytes()),
    'source_snapshots': len(manifest['source_sha256']), 'archive_members': archive_members,
    'native_observations': 108, 'native_reference_pairs': native_pairs,
    'native_warning_history_pairs': warning_history_pairs,
    'routes': [{'mode': mode, 'history': history, 'route': route, 'count': count}
               for (mode, history, route), count in sorted(routes.items())],
    'costs': summary, 'complete_closure_certified': False, 'adaptive_noninterference_proved': False,
    'scope': 'Three independent workers, two repeated blocks each. Previously verified seeds; direct cc1 execution. Same native prefix/effects, full-context guard versus computation binding. Misses run native without cache filling. Costs exclude setup, preloading, prior producers and postprocess observation.'}
if '--read-only' not in sys.argv:
    (root / 'independent-scope-audit.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, indent=2))
