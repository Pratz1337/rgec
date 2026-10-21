"""Audit retained native slice evidence by parsing original bytes, no local jobs."""
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

sys.dont_write_bytecode = True
root = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
from rgec_native_effect_probe import signature
from rgec_backend_probe import queue_signature


def sha(data): return hashlib.sha256(data).hexdigest()


class Reader:
    def __init__(self, data): self.data, self.offset = data, 0
    def number(self):
        value = struct.unpack_from('<Q', self.data, self.offset)[0]; self.offset += 8
        return value
    def field(self):
        length = self.number(); value = self.data[self.offset:self.offset + length]
        self.offset += length; assert len(value) == length
        return value
    def done(self): assert self.offset == len(self.data)


def packet(data):
    assert data[:6] in (b'RGECB2', b'RGECB3')
    reader = Reader(data); reader.offset = 6
    first = reader.field(); computation = reader.field() if data[:6] == b'RGECB2' else first
    bound = first if data[:6] == b'RGECB2' else None
    assert reader.number() == 1 and reader.number() == 0
    operations = []
    for _ in range(reader.number()): operations.append((reader.number(), reader.number(), reader.field()))
    reader.done()
    return bound, computation, operations


def project(operations, folder, label):
    result = []; snapshots = []
    for kind, position, data in operations:
        if kind != 6: result.append((kind, position, sha(data))); continue
        reader = Reader(data); name = reader.field().decode()
        size, limit = reader.number(), reader.number(); identifier, bitcode = reader.field(), reader.field(); reader.done()
        result.append((kind, position, name, size, limit, sha(identifier)))
        filename = label + '-generated-' + str(len(snapshots))
        assert (folder / (filename + '.bc')).read_bytes() == bitcode
        ir = (folder / (filename + '.ll')).read_bytes()
        definitions = [line for line in ir.decode().splitlines() if line.startswith('define ')]
        assert any('@' + name + '(' in line or '@"' + name + '"(' in line for line in definitions)
        assert not (folder / (filename + '.verify.stdout')).read_bytes()
        assert not (folder / (filename + '.verify.stderr')).read_bytes()
        snapshots.append({'name': name, 'size': size, 'limit': limit, 'identifier_sha256': sha(identifier),
            'bitcode_bytes': len(bitcode), 'bitcode_sha256': sha(bitcode), 'definition_count': len(definitions),
            'ir_sha256': sha(ir), 'verify_returncode': 0})
    return result, snapshots


manifest_bytes = (root / 'evidence.json').read_bytes(); manifest = json.loads(manifest_bytes.decode('utf-8'))
assert 'error' not in manifest and len(manifest['sandboxes']) == 5
for path, digest in manifest['source_sha256'].items(): assert sha((root / Path(path.replace('\\', '/')).name).read_bytes()) == digest
loaded_helpers = {}
for name in ('rgec_native_effect_probe', 'rgec_backend_probe', 'rgec_native_event_probe', 'modal_recipient_entry'):
    actual = sha(Path(sys.modules[name].__file__).read_bytes())
    assert actual == sha((root / (name + '.py')).read_bytes())
    loaded_helpers[name] = actual
assert sha((root / 'native-build.py').read_bytes()) == manifest['build_script_sha256']
if 'recovered_from_root' in manifest:
    prior_root = root.parent / manifest['recovered_from_root']
    original = (prior_root / 'evidence.json').read_bytes()
    assert sha(original) == manifest['recovered_from_manifest_sha256']
    assert (root / 'interrupted-attempt-evidence.json').read_bytes() == original
    prior = json.loads(original.decode('utf-8'))
    assert 'error' in prior and manifest['interrupted_worker'] == prior['sandboxes'][4]
    for old, imported in zip(prior['sandboxes'][:4], manifest['sandboxes'][:4]):
        assert imported == dict(old, artifact_root=prior_root.name)
if 'durable_volume' in manifest:
    report_root = Path(manifest['native_report_root'].replace('\\', '/'))
    assert sha((report_root / 'evidence.json').read_bytes()) == manifest['native_report_manifest_sha256']
    report = json.loads((report_root / 'evidence.json').read_text(encoding='utf-8'))
    assert report['sandboxes'][0]['tool_sha256'] == manifest['baseline_tool_sha256']
members = 0; phases = {}; folders = {}
for worker in manifest['sandboxes']:
    assert worker['returncode'] == 0
    if worker.get('termination_mode') == 'native worker entrypoint exits':
        assert worker['cleanup_returncode'] == 0
        phase = worker['phase']
        config_path = root / (phase + '-retention-config.json')
        assert sha(config_path.read_bytes()) == worker['retention_config_sha256']
        config = json.loads(config_path.read_text(encoding='utf-8'))
        assert config['prefix'] == manifest['durable_volume_prefix'] == root.name
        assert config['tool_sha256'] == worker['tool_sha256'] == manifest['baseline_tool_sha256']
        expected_previous = () if phase == 'capture' else ('capture',) if phase == 'producer' else ('capture', 'producer')
        assert config['transfer_sha256'] == {p: next(r['raw_archive_sha256'] for r in manifest['sandboxes'] if r['phase'] == p) for p in expected_previous}
        durable = json.loads((root / (phase + '-durable-result.json')).read_text(encoding='utf-8'))
        assert durable['returncode'] == 0 and durable['tool_sha256'] == worker['tool_sha256']
        assert durable['raw.tar.gz_sha256'] == worker['raw_archive_sha256']
        assert sha((root / (phase + '.stdout')).read_bytes()) == durable['stdout_sha256']
        assert sha((root / (phase + '.stderr')).read_bytes()) == durable['stderr_sha256']
    else:
        assert worker['cleanup_returncode'] == 137
    folder = (root.parent / worker['artifact_root'] if 'artifact_root' in worker else root) / worker['phase']
    folders[worker['phase']] = folder
    assert sha((folder / 'raw.tar.gz').read_bytes()) == worker['raw_archive_sha256']
    with tarfile.open(folder / 'raw.tar.gz') as archive:
        for member in archive:
            assert member.isfile() and member.name == 'raw/' + Path(member.name).name
            assert archive.extractfile(member).read() == (folder / Path(member.name).name).read_bytes()
            members += 1
    evidence = json.loads((folder / 'evidence.json').read_text(encoding='utf-8')); phases[worker['phase']] = evidence
    assert all(evidence['tool_sha256'][path] == digest for path, digest in worker['tool_sha256'].items())
    assert evidence['tool_sha256'] == next(iter(phases.values()))['tool_sha256']
capture = phases['capture']; producer = phases['producer']
capture_folder, producer_folder = folders['capture'], folders['producer']
assert len(capture['cases']) == len(producer['cases']) == 6
assert producer['protected_input_files'] and producer['map_open_returncode'] == 1
assert b'PermissionError' in (producer_folder / 'map-open.stderr').read_bytes()
sizes = []; snapshot_count = 0
for case, produced in zip(capture['cases'], producer['cases']):
    assert case['name'] == produced['name']
    original = (capture_folder / (case['source'] + '.original')).read_bytes()
    changed = (capture_folder / (case['source'] + '.captured.source')).read_bytes()
    assert sha(original) == case['original_sha256'] and changed.endswith(original)
    assert sha(changed) == case['captured_source_sha256']
    assert changed[:-len(original)] == b'#pragma clang diagnostic ignored "-W#warnings"\n#warning RGEC real frontend history one\n#warning RGEC real frontend history two\n#pragma clang diagnostic warning "-Wframe-larger-than="\n'
    bound = (capture_folder / (case['name'] + '-full.key')).read_bytes()
    assert bound == (capture_folder / (case['name'] + '-sliced.key')).read_bytes()
    reader = Reader(bound); arguments = [reader.field().decode() for _ in range(reader.number())]
    assert arguments == case['arguments']
    projections = {}
    for mode in ('full', 'sliced'):
        recorded = case[mode]; native = case['native']
        assert all(recorded[k] == native[k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256', 'object_sha256'))
        for arm, row in ((mode, recorded), ('native', native)):
            label = case['name'] + '-' + arm + '-' + ('record' if arm != 'native' else 'native')
            for suffix in ('stdout', 'stderr', 'control'):
                assert sha((capture_folder / (label + '.' + suffix)).read_bytes()) == row[suffix + '_sha256']
            assert sha((capture_folder / (label + '.object.o')).read_bytes()) == row['object_sha256']
        label = case['name'] + '-' + mode; folder = producer_folder; row = produced[mode]
        raw = (folder / (label + '.packet')).read_bytes()
        delivery = (folder / (label + '.compact.packet')).read_bytes()
        actual_bound, computation, ops = packet(raw)
        assert actual_bound == bound
        size = struct.unpack_from('<Q', raw, 6)[0]
        assert delivery == b'RGECB3' + raw[14 + size:]
        _, compact_computation, compact_ops = packet(delivery)
        assert computation == compact_computation and ops == compact_ops
        assert row['packet_sha256'] == sha(raw) and row['delivery_sha256'] == sha(delivery)
        assert row['key_sha256'] == sha(bound) and row['computation_key_sha256'] == sha(computation)
        assert row['returncode'] == native['returncode'] == 0
        assert sha((folder / (label + '.object.o')).read_bytes()) == row['object_sha256'] == native['object_sha256']
        assert not (folder / (label + '.fresh.control')).read_bytes()
        assert row['fresh_frontend_returncode'] == 1 and b'error:' in (folder / (label + '.fresh.stderr')).read_bytes()
        projection, snapshots = project(ops, folder, label)
        assert json.loads(json.dumps(projection)) == row['projection']
        assert snapshots == row['generated_snapshots'] and snapshots
        assert len(delivery) == row['packet_bytes']
        projections[mode] = projection; snapshot_count += len(snapshots)
    assert projections['full'] == projections['sliced']
    sizes.append({'name': case['name'], 'full_delivery_bytes': produced['full']['packet_bytes'],
        'sliced_delivery_bytes': produced['sliced']['packet_bytes'],
        'full_snapshot_bytes': sum(s['bitcode_bytes'] for s in produced['full']['generated_snapshots']),
        'sliced_snapshot_bytes': sum(s['bitcode_bytes'] for s in produced['sliced']['generated_snapshots']),
        'full_definition_counts': [s['definition_count'] for s in produced['full']['generated_snapshots']],
        'sliced_definition_counts': [s['definition_count'] for s in produced['sliced']['generated_snapshots']]})
costs = collections.defaultdict(list); matches = collections.Counter(); statuses = collections.Counter()
history_pairs = 0; limit_pairs = 0; observations = 0
for phase in ('replay-0', 'replay-1', 'replay-2'):
    evidence = phases[phase]; folder = folders[phase]; rows = evidence['rows']; assert len(rows) == 216
    randomizer = random.Random(6531); plan = []
    for case in capture['cases']:
        for block in range(2):
            order = [(prefix, policy, mode) for prefix in ('ignored', 'warning')
                for policy in ('ignored', 'warning', 'error') for mode in ('native', 'full', 'sliced')]
            randomizer.shuffle(order)
            plan.extend((case['name'], block, prefix, policy, mode) for prefix, policy, mode in order)
    assert plan == [(row['name'], row['block'], row['prefix'], row['policy'], row['mode']) for row in rows]
    for row in rows:
        case = next(case for case in capture['cases'] if case['name'] == row['name'])
        original = (capture_folder / (case['source'] + '.original')).read_bytes()
        changed = ('#pragma clang diagnostic ' + row['prefix'] + ' "-W#warnings"\n'
            '#warning RGEC real frontend history one\n#warning RGEC real frontend history two\n'
            '#pragma clang diagnostic ' + row['policy'] + ' "-Wframe-larger-than="\n').encode() + original
        assert sha(changed) == row['source_sha256']
        assert row['argv'][1:] == ['-cc1'] + case['arguments']
        label = row['label']; observations += 1
        for suffix in ('stdout', 'stderr', 'control'):
            assert sha((folder / (label + '.' + suffix)).read_bytes()) == row[suffix + '_sha256']
        assert sha((folder / (label + '.held')).read_bytes()) == row['held_fd_content_sha256']
        object_path = folder / (label + '.object.o')
        assert (sha(object_path.read_bytes()) if object_path.is_file() else None) == row['object_sha256']
        if row['mode'] != 'native':
            control = (folder / (label + '.control')).read_bytes(); assert control[:6] == b'RGECQ1'
            length = struct.unpack_from('<Q', control, 6)[0]; bound = control[14:14 + length]
            assert bound == (folder / (label + '.query')).read_bytes() and sha(bound) == row['query_sha256']
            assert control[14 + length:] == b'RGECH1' and row['receipt'] == 'RGECH1'
        reference = next(other for other in rows if other['name'] == row['name'] and other['block'] == row['block']
            and other['prefix'] == row['prefix'] and other['policy'] == row['policy'] and other['mode'] == 'native')
        actual = {'status_and_streams_match': all(row[k] == reference[k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256')),
            'object_bytes_match': row['object_sha256'] == reference['object_sha256'],
            'structural_effects_match': signature(row) == signature(reference),
            'event_roles_match': queue_signature(row['events']) == queue_signature(reference['events'])}
        assert all(row[name] == value for name, value in actual.items())
        if row['mode'] != 'native':
            for name, value in actual.items(): matches[(name, value)] += 1
        diagnostic = (folder / (label + '.stderr')).read_bytes()
        warnings = re.findall(rb'(?m)^(\d+) warnings? generated\.$', diagnostic)
        errors = re.findall(rb'(?m)^(\d+) errors? generated\.$', diagnostic)
        combined = re.findall(rb'(?m)^(\d+) warnings? and (\d+) errors? generated\.$', diagnostic)
        row['_counts'] = (int(warnings[0]) if warnings else int(combined[0][0]) if combined else 0,
                          int(errors[0]) if errors else int(combined[0][1]) if combined else 0)
        statuses[(row['policy'], row['returncode'])] += 1
        assert row['returncode'] == (1 if row['policy'] == 'error' else 0)
        assert all(row[key] >= 0 for key in ('child_cpu_seconds', 'service_cpu_seconds', 'helper_wall_seconds'))
        costs[(row['name'], row['prefix'], row['policy'], row['mode'])].append(
            (row['child_cpu_seconds'] + row['service_cpu_seconds'], row['helper_wall_seconds']))
    for case in capture['cases']:
        for block in range(2):
            ignored = next(row for row in rows if row['name'] == case['name'] and row['block'] == block and row['mode'] == 'native' and row['policy'] == 'warning' and row['prefix'] == 'ignored')
            warning = next(row for row in rows if row['name'] == case['name'] and row['block'] == block and row['mode'] == 'native' and row['policy'] == 'warning' and row['prefix'] == 'warning')
            assert warning['_counts'][0] == ignored['_counts'][0] + 2; history_pairs += 1
    for source in ('adler32.c', 'deflate.c', 'FuzzerUtil.cpp'):
        for block in range(2):
            limited = next(row for row in rows if row['name'] == source + '-limit-1' and row['block'] == block and row['mode'] == 'native' and row['policy'] == 'error' and row['prefix'] == 'ignored')
            unlimited = next(row for row in rows if row['name'] == source + '-limit-0' and row['block'] == block and row['mode'] == 'native' and row['policy'] == 'error' and row['prefix'] == 'ignored')
            assert unlimited['_counts'][1] > limited['_counts'][1] > 0; limit_pairs += 1
result = {'manifest_sha256': sha(manifest_bytes), 'auditor_sha256': sha(Path(__file__).read_bytes()),
    'loaded_helper_sha256': loaded_helpers,
    'source_snapshots': len(manifest['source_sha256']),
    'archive_members': members, 'isolated_productions': 12, 'genuine_generated_snapshots_verified': snapshot_count,
    'native_observations': observations, 'native_reference_pairs': observations * 2 // 3,
    'comparison_results': [{'observation': name, 'match': match, 'count': count} for (name, match), count in sorted(matches.items())],
    'native_warning_history_pairs': history_pairs, 'native_error_limit_pairs': limit_pairs,
    'policy_status_counts': [{'policy': policy, 'returncode': status, 'count': count} for (policy, status), count in sorted(statuses.items())],
    'sizes': sizes, 'costs': [dict(name=name, prefix=prefix, policy=policy, mode=mode, observations=len(values),
        median_total_measured_cpu_seconds=statistics.median(value[0] for value in values),
        median_helper_wall_seconds=statistics.median(value[1] for value in values))
        for (name, prefix, policy, mode), values in sorted(costs.items())],
    'complete_closure_certified': False, 'adaptive_noninterference_proved': False,
    'scope': 'Three real workers, two blocks each; same seeded genuine packets. Direct native cc1 calls; component timing includes child and service feed CPU, excludes capture, producer, setup, verification and postprocess. No full-workflow or population utility claim.'}
if '--read-only' not in sys.argv:
    (root / 'independent-slice-audit.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, indent=2))
