"""Audit retained real compiler reports without executing a local compiler."""
import collections
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import tarfile


def sha(data): return hashlib.sha256(data).hexdigest()


def packet(data):
    assert data[:6] == b'RGECB1'
    offset = 6
    def number():
        nonlocal offset
        value = struct.unpack_from('<Q', data, offset)[0]; offset += 8
        return value
    def field():
        nonlocal offset
        length = number(); value = data[offset:offset + length]; offset += length
        assert len(value) == length
        return value
    bound = field(); reusable = number()
    for _ in range(number()): number(); number(); field(); field()
    operations = []
    for _ in range(number()): operations.append((number(), number(), field()))
    assert offset == len(data)
    return bound, reusable, operations


for argument in sys.argv[1:]:
    root = Path(argument).resolve(); raw_manifest = (root / 'evidence.json').read_bytes()
    manifest = json.loads(raw_manifest); counts = collections.Counter(); rows = []
    baseline_folder = None
    if 'baseline_root' in manifest:
        baseline_root = Path(manifest['baseline_root']).resolve()
        assert sha((baseline_root / 'evidence.json').read_bytes()) == manifest['baseline_manifest_sha256']
        baseline_folder = baseline_root / 'reports'
        assert sha((baseline_folder / 'raw.tar.gz').read_bytes()) == manifest['baseline_archive_sha256']
        assert sha((root / 'native-build.py').read_bytes()) == manifest['build_script_sha256']
    if 'durable_volume' in manifest:
        original_root = Path(manifest['recovered_from_root']).resolve()
        original_bytes = (original_root / 'evidence.json').read_bytes()
        assert original_bytes == (root / 'interrupted-attempt-evidence.json').read_bytes()
        assert sha(original_bytes) == manifest['recovered_from_manifest_sha256']
        original = json.loads(original_bytes)
        assert manifest['interrupted_worker_observed_returncode'] == 137
        assert 'raw_archive_sha256' not in original['sandboxes'][0]
        assert sha((root / 'prior-packets.tar.gz').read_bytes()) == manifest['prior_packet_archive_sha256']
        assert sha((root / 'retention-config.json').read_bytes()) == manifest['retention_config_sha256']
        with tarfile.open(root / 'prior-packets.tar.gz') as stream:
            for member in stream:
                assert member.isfile() and member.name == 'raw/' + Path(member.name).name
                data = stream.extractfile(member).read()
                assert data == (baseline_folder / Path(member.name).name).read_bytes()
                assert sha(data) == manifest['prior_packet_sha256'][Path(member.name).name]
        durable = json.loads((root / 'durable-result.json').read_bytes())
        assert durable['returncode'] == 0
        assert durable['tool_sha256'] == original['sandboxes'][0]['tool_sha256']
        assert sha((root / 'reports.stdout').read_bytes()) == durable['reports.stdout_sha256']
        assert sha((root / 'reports.stderr').read_bytes()) == durable['reports.stderr_sha256']
    for name, expected in manifest['source_sha256'].items():
        assert sha((root / Path(name).name).read_bytes()) == expected
        counts['frozen_sources'] += 1
    sys.dont_write_bytecode = True; sys.path.insert(0, str(root))
    from rgec_native_effect_probe import signature
    for worker in manifest['sandboxes']:
        if worker.get('termination_mode') == 'native worker entrypoint exits':
            assert worker['returncode'] == worker['cleanup_returncode'] == 0
            assert worker['raw_archive_sha256'] == durable['raw.tar.gz_sha256']
        else: assert worker['cleanup_returncode'] == 137
        folder = root / worker['phase']; archive = folder / 'raw.tar.gz'
        assert sha(archive.read_bytes()) == worker['raw_archive_sha256']
        with tarfile.open(archive) as stream:
            for member in stream:
                assert member.isfile() and member.name == 'raw/' + Path(member.name).name
                assert stream.extractfile(member).read() == (folder / Path(member.name).name).read_bytes()
                counts['archive_members'] += 1
        evidence = json.loads((folder / 'evidence.json').read_bytes())
        assert all(evidence['tool_sha256'][k] == v for k, v in worker['tool_sha256'].items()
                   if k in evidence['tool_sha256'])
        for case in evidence['rows']:
            assert sha((folder / (case['source'] + '.original')).read_bytes()) == case['source_sha256']
            summary = {'name': case['name'], 'profile': case['profile'], 'observations': {}}
            if 'replay_packet_origin' in case:
                assert baseline_folder is not None
                origin = case['replay_packet_origin']; assert origin.startswith('frozen-v23/')
                raw_packet = (baseline_folder / origin.split('/')[1]).read_bytes()
                assert sha(raw_packet) == case['replay_packet_sha256']
                packet(raw_packet)
                assert case['record']['receipt'] == case['replay']['receipt'] == 'RGECP1'
                assert case['record']['key_sha256'] is case['replay']['key_sha256'] is None
                summary['replay_packet_origin'] = origin
                counts['actual_old_packet_bypasses'] += 1
            for mode in ('native', 'native-repeat', 'record', 'replay'):
                if mode not in case: continue
                row = case[mode]; label = row['case']; streams = {}
                for suffix, key in (('stdout', 'stdout_sha256'), ('stderr', 'stderr_sha256'),
                    ('control', 'control_sha256'), ('object.o', 'object_sha256'), ('held.o', 'held_fd_content_sha256')):
                    path = folder / (label + '.' + suffix)
                    if row[key] is None: assert not path.exists(); continue
                    raw = path.read_bytes(); assert sha(raw) == row[key], path
                    counts['raw_hashes'] += 1; streams[suffix] = raw
                if row['stats_file_sha256'] is not None:
                    stats_raw = (folder / (case['name'] + '-' + mode + '.stats.json')).read_bytes()
                    assert sha(stats_raw) == row['stats_file_sha256']; counts['raw_hashes'] += 1
                    stats = json.loads(stats_raw)
                else: stats = None
                control = streams['control']
                if mode == 'record' and 'info' in row:
                    actual = (folder / (case['name'] + '-record.packet')).read_bytes()
                    assert actual == control
                    bound, reusable, operations = packet(actual)
                    assert sha(bound) == row['key_sha256'] and reusable == row['info']['reusable']
                    assert bound == (folder / (case['name'] + '-record.key')).read_bytes()
                    assert [{'kind': k, 'offset': p, 'bytes': len(d), 'sha256': sha(d)} for k,p,d in operations] == row['info']['operations']
                    object_bytes = bytearray()
                    for kind, position, data in operations:
                        if kind == 0: object_bytes.extend(data)
                        elif kind == 1:
                            assert position + len(data) <= len(object_bytes)
                            object_bytes[position:position + len(data)] = data
                    assert bytes(object_bytes) == streams['object.o']
                    counts['actual_recorded_packets'] += 1
                if mode == 'replay':
                    if control.startswith(b'RGECQ1'):
                        length = struct.unpack_from('<Q', control, 6)[0]
                        assert sha(control[14:14 + length]) == row['key_sha256']
                        assert control[14 + length:] == row['receipt'].encode()
                        counts['actual_queries'] += 1
                    else: assert control == row['receipt'].encode()
                    counts['hits'] += row['receipt'] == 'RGECH1'
                    counts['private_replays'] += row['receipt'] == 'RGECP1'
                report = streams['stderr'].decode('utf-8', errors='replace')
                # Durations remain raw. Only names of native timing rows are projected.
                timing_names = [m.group(1).strip() for m in re.finditer(
                    r'^\s*(?:(?:-?[\d.]+\s*\(\s*-?[\d.]+%\)|-----)\s+){1,4}(.+?)\s*$', report, re.M)]
                summary['observations'][mode] = {'returncode': row['returncode'],
                    'receipt': row['receipt'], 'stderr_bytes': len(streams['stderr']),
                    'ir_dump_after_count': report.count('*** IR Dump After'),
                    'pass_timing_section_count': report.count('... Pass execution timing report ...'),
                    'timing_row_names': timing_names,
                    'timing_row_name_counts': dict(collections.Counter(timing_names)), 'stats': stats}
                counts['actual_compiler_observations'] += 1
            native, repeat = case['native'], case['native-repeat']
            fields = ('returncode', 'stdout_sha256', 'stderr_sha256')
            summary['native_repeat_streams_match'] = all(native[k] == repeat[k] for k in fields)
            if 'native_repeat_streams_match' in case:
                assert summary['native_repeat_streams_match'] == case['native_repeat_streams_match']
            if 'record_matches_native' in case:
                assert all(native[k] == case['record'][k] for k in fields) == case['record_matches_native']
            if 'replay' in case:
                replay = case['replay']
                summary['replay_matches_native'] = all(native[k] == replay[k] for k in fields)
                summary['replay_object_matches_native'] = native['object_sha256'] == replay['object_sha256']
                assert summary['replay_matches_native'] == case['replay_matches_native']
                assert summary['replay_object_matches_native'] == case['replay_object_matches_native']
                assert (signature(native) == signature(replay)) == case['replay_structural_effects_match']
                assert (native['stats_file_sha256'] == replay['stats_file_sha256']) == case['replay_stats_match_native']
                counts['literal_stream_mismatches'] += not summary['replay_matches_native']
                counts['object_matches'] += summary['replay_object_matches_native']
                summary['structural_effects_match'] = case['replay_structural_effects_match']
                summary['stats_file_matches'] = case['replay_stats_match_native']
                for projection in ('ir_dump_after_count', 'pass_timing_section_count', 'timing_row_names', 'timing_row_name_counts', 'stats'):
                    summary['replay_' + projection + '_matches'] = (
                        summary['observations']['native'][projection] == summary['observations']['replay'][projection])
            rows.append(summary)
    result = {'root': str(root), 'manifest_sha256': sha(raw_manifest),
        'auditor_sha256': sha(Path(__file__).read_bytes()), 'counts': dict(counts),
        'suite_complete': 'error' not in manifest, 'rows': rows,
        'general_native_admission_certified': False, 'adaptive_noninterference_proved': False}
    (root / 'independent-report-audit.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'root': str(root), 'manifest_sha256': sha(raw_manifest),
        'counts': dict(counts), 'suite_complete': result['suite_complete']}))
