"""Inspect retained real workflows, packet bindings and live-worker access results."""
import collections
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import statistics
import struct
import sys
import tarfile

sys.dont_write_bytecode = True


def sha(data):
    return hashlib.sha256(data).hexdigest()


root = Path(sys.argv[1])
manifest = json.loads((root / 'evidence.json').read_text())
counts = collections.Counter()


def checked(folder, name, digest):
    data = (folder / name).read_bytes()
    assert sha(data) == digest, name
    counts['recorded_raw_hashes'] += 1
    return data


for path, digest in manifest['source_sha256'].items():
    checked(root, Path(path).name, digest)
    counts['frozen_source_snapshots'] += 1
commands = json.loads(checked(root, 'zlib-native-commands.json', manifest['native_commands_sha256']))
preload = json.loads(checked(root, 'preload.json', manifest['preload_sha256']))
assert len(commands) == 23 and sum('-c' in args for args in commands) == 19
assert len(preload['receipts']) == len(preload['driver_plans']) == 19
prior_manifests = [path for path in root.parent.glob('rgec-modal-full-zlib-authenticated-*/evidence.json')
                   if sha(path.read_bytes()) == manifest['prior_authenticated_manifest_sha256']]
assert len(prior_manifests) == 1
prior_root = prior_manifests[0].parent
prior = json.loads(checked(prior_root, 'evidence.json', manifest['prior_authenticated_manifest_sha256']))
prior_audit = json.loads((prior_root / 'independent-full-zlib-store-audit.json').read_text())
assert prior_audit['complete_functional_suite']
assert prior_audit['manifest_sha256'] == manifest['prior_authenticated_manifest_sha256']
assert prior['tool_sha256'] == manifest['tool_sha256']
prior_cold = json.loads((prior_root / 'policy-cold/evidence.json').read_text())
unwrapped_root = root.parent / 'rgec-modal-full-zlib-native-2026-10-05-v20-v2'
unwrapped = json.loads(checked(unwrapped_root, 'evidence.json', prior['native_reference_manifest_sha256']))
unwrapped_build = json.loads((unwrapped_root / 'v20/evidence.json').read_text())
# This reference executes the original compiler, not its historical wrapper.
# Current wrapper identity is checked independently on every current worker.
assert unwrapped['sandboxes'][0]['tool_sha256']['/usr/local/bin/clang'] == manifest['tool_sha256']['/usr/local/bin/clang']
assert unwrapped_build['outputs'] == prior_cold['outputs']
spec = importlib.util.spec_from_file_location('frozen_store', root / 'backend_recipe_store.py')
store = importlib.util.module_from_spec(spec)
spec.loader.exec_module(store)


def arguments(bound):
    count = struct.unpack_from('<Q', bound)[0]
    offset, result = 8, []
    assert count < 10000
    for _ in range(count):
        size = struct.unpack_from('<Q', bound, offset)[0]
        offset += 8
        result.append(bound[offset:offset + size].decode())
        offset += size
    return result


for receipt, plan in zip(preload['receipts'], preload['driver_plans']):
    action = next(row for row in prior_cold['compiler_actions'] if row.get('query_sha256') == plan['validated_native_query_sha256'])
    bound = checked(prior_root / 'policy-cold', action['label'] + '.query', action['query_sha256'])
    packet = checked(prior_root / 'policy-cold', action['label'] + '.reply', receipt['packet_sha256'])
    assert packet == bytes.fromhex(preload['packets'][receipt['profile']])
    assert receipt['context'] == preload['context'] and not receipt['complete_closure_certified']
    assert sha(store.computation_key(bound)) == receipt['key_sha256']
    assert arguments(bound) == plan['native_cc1_arguments'] and action['arguments'] == plan['arguments']
    resource_dir = plan['native_cc1_arguments'][plan['native_cc1_arguments'].index('-resource-dir') + 1]
    assert plan['wrapped_argv'] == ['/rgec-driver/clang-7', '-no-canonical-prefixes', '-ccc-install-dir', '/usr/local/bin', '-resource-dir', resource_dir] + plan['arguments']
    assert any(row.get('origin') == receipt['origin'] for row in prior['store_audit'])
    counts['previously_produced_packets_reauthenticated'] += 1

rng, expected_order = random.Random(6317), []
for block in range(3):
    modes = ['native', 'local-warm']
    rng.shuffle(modes)
    expected_order.extend({'block': block, 'mode': mode, 'phase': 'block-' + str(block) + '-' + mode} for mode in modes)
assert manifest['planned_order'] == expected_order and len(manifest['sandboxes']) == 6
phases, costs, negative_cpu_roundoff = {}, [], []
for row, planned in zip(manifest['sandboxes'], expected_order):
    assert all(row[key] == value for key, value in planned.items())
    assert row['returncode'] == row['authority_returncode'] == 0 and row['cleanup_returncode'] == 137
    assert row['tool_sha256'] == manifest['tool_sha256']
    folder = root / row['phase']
    checked(folder, 'raw.tar.gz', row['raw_archive_sha256'])
    with tarfile.open(folder / 'raw.tar.gz') as stream:
        for member in stream:
            assert member.isfile() and member.name == 'raw/' + Path(member.name).name
            assert stream.extractfile(member).read() == (folder / Path(member.name).name).read_bytes()
            counts['archive_members'] += 1
    data = json.loads((folder / 'evidence.json').read_text())
    phases[row['phase']] = data
    assert data['source_bodies_unchanged'] and data['experimental_fixed_workflow'] and len(data['phases']) == 9
    assert data['artifact_directory'] == '/rgec-private/zlib'
    assert data['phases'][1]['argv'] == ['/usr/bin/make', '-j1', 'CC=/rgec-zlib-compiler']
    assert data['outputs'] == prior_cold['outputs'] and data['roundtrips'] == prior_cold['roundtrips']
    for relative, digest in data['input_sha256'].items():
        checked(folder, 'input-' + relative.replace('/', '__'), digest)
    for phase in data['phases']:
        assert phase['returncode'] == 0
        for metric in ('child_cpu_seconds', 'broker_self_cpu_seconds', 'helper_wall_seconds'):
            if phase[metric] < 0:
                # Sequential floating-point subtraction can produce tiny
                # negative CPU deltas. Retain them; never excuse wall failures.
                assert metric != 'helper_wall_seconds' and phase[metric] >= -1e-12
                negative_cpu_roundoff.append({'worker': row['phase'], 'phase': phase['label'],
                                             'metric': metric, 'raw_seconds': phase[metric]})
        for suffix in ('stdout', 'stderr'):
            checked(folder, phase['label'] + '.' + suffix, phase[suffix + '_sha256'])
        counts['actual_workflow_phases'] += 1
    test_output = (folder / 'upstream-test.stdout').read_bytes()
    assert b'*** zlib test OK ***' in test_output and b'*** zlib 64-bit test OK ***' in test_output
    for trip in data['roundtrips']:
        name = Path(trip['path']).name
        source = checked(folder, 'roundtrip-' + name + '.input', trip['input_sha256'])
        assert source == (folder / ('decompress-' + name + '.stdout')).read_bytes()
        assert source == gzip.decompress((folder / ('compress-' + name + '.stdout')).read_bytes())
        counts['actual_repository_roundtrips'] += 1
    for relative, record in data['outputs'].items():
        raw = checked(folder, 'output-' + relative.replace('/', '__'), record['sha256'])
        assert len(raw) == record['bytes']
        if relative.endswith('.o'):
            assert raw[:4] == b'\x7fELF'
            counts['native_objects'] += 1
    assert sorted(action['arguments'] for action in data['compiler_actions']) == sorted(commands)
    for action in data['compiler_actions']:
        assert action['returncode'] == 0
        for suffix in ('control', 'stdout', 'stderr', 'output'):
            checked(folder, action['label'] + '.' + suffix, action[suffix + '_sha256'])
        if action['query_emitted']:
            bound = checked(folder, action['label'] + '.query', action['query_sha256'])
            packet = checked(folder, action['label'] + '.reply', action['reply_sha256'])
            plan = next(plan for plan in preload['driver_plans'] if plan['arguments'] == action['arguments'])
            assert arguments(bound) == plan['native_cc1_arguments'] and action['validated_driver_plan']
            assert packet == bytes.fromhex(preload['packets'][action['arguments'][action['arguments'].index('-o') + 1]])
            assert store.packet_key(packet) == store.computation_key(bound)
            assert (folder / (action['label'] + '.control')).read_bytes() == b'RGECQ1' + struct.pack('<Q', len(bound)) + bound + b'RGECH1'
            assert action['store_route'] == 'authenticated-hit'
            counts['actual_authenticated_recipient_hits'] += 1
        else:
            assert not action['receipt']
        counts['actual_compiler_and_link_actions'] += 1
    assert sum(action['query_emitted'] for action in data['compiler_actions']) == (19 if row['mode'] == 'local-warm' else 0)
    if row['mode'] == 'local-warm':
        assert len(data['trusted_local_store_audit']) == 19
        for entry in data['trusted_local_store_audit']:
            receipt = next(receipt for receipt in preload['receipts'] if receipt['profile'] == entry['profile'])
            assert entry['key_sha256'] == receipt['key_sha256'] and entry['route'] == 'authenticated-hit'
    access = json.loads(checked(root, row['phase'] + '.authority.stdout', row['authority_stdout_sha256']))
    assert len(access) == 7 and not (root / (row['phase'] + '.authority.stderr')).read_bytes()
    for observation in access[:-1]:
        assert observation['returncode'] == 1 and not bytes.fromhex(observation['stdout_hex'])
        assert b'PermissionError: [Errno 13] Permission denied' in bytes.fromhex(observation['stderr_hex'])
        counts['live_worker_private_read_denials'] += 1
    assert access[-1]['path'] == '/workspace/backend-continuation/project/zlib.h'
    assert access[-1]['returncode'] == 0 and bytes.fromhex(access[-1]['stdout_hex']) == b'readable\n'
    counts['live_worker_own_source_read_controls'] += 1
    build = data['phases'][1]
    costs.append(dict(planned, child_cpu_seconds=build['child_cpu_seconds'], broker_self_cpu_seconds=build['broker_self_cpu_seconds'], total_measured_cpu_seconds=build['child_cpu_seconds'] + build['broker_self_cpu_seconds'], helper_wall_seconds=build['helper_wall_seconds']))

for block in range(3):
    native, warm = phases['block-' + str(block) + '-native'], phases['block-' + str(block) + '-local-warm']
    for actual, reference in zip(warm['phases'], native['phases']):
        assert all(actual[key] == reference[key] for key in ('returncode', 'stdout_sha256', 'stderr_sha256'))
    for actual, reference in zip(warm['compiler_actions'], native['compiler_actions']):
        assert all(actual[key] == reference[key] for key in ('arguments', 'returncode', 'stdout_sha256', 'stderr_sha256', 'output_sha256'))
        def structure(action):
            return {**{key: value for key, value in action['after'].items() if key not in ('ino', 'mtime_ns', 'ctime_ns')}, 'inode_changed': action['before'].get('ino') != action['after'].get('ino')}
        def roles(action):
            return [(event['mask'], 'temporary' if event['name'].endswith('.tmp') else event['name']) for event in action['events']]
        assert structure(actual) == structure(reference) and roles(actual) == roles(reference)
        counts['native_compiler_effect_comparisons'] += 1
assert counts['actual_authenticated_recipient_hits'] == 57 and counts['live_worker_private_read_denials'] == 36
medians = {mode: {metric: statistics.median(row[metric] for row in costs if row['mode'] == mode) for metric in ('child_cpu_seconds', 'broker_self_cpu_seconds', 'total_measured_cpu_seconds', 'helper_wall_seconds')} for mode in ('native', 'local-warm')}
result = {'root': str(root), 'manifest_sha256': sha((root / 'evidence.json').read_bytes()), 'counts': dict(counts), 'complete_functional_suite': True, 'cost_blocks': costs, 'build_medians': medians, 'negative_cpu_roundoff_retained': negative_cpu_roundoff, 'limited_structural_and_event_projection': True, 'adaptive_noninterference_proved': False, 'limits': 'Three fixed-workflow independent worker pairs; previously produced packets preloaded. No local misses, producer amortization, setup/startup/transfer/charges/reservation costs, live broker mutation/concurrency, contextual metadata coupling or release guarantee.'}
if '--read-only' not in sys.argv:
    (root / 'independent-cloud-zlib-store-audit.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, indent=2))
