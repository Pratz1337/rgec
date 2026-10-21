"""Re-derive native map results from retained cloud bytes; no compiler runs."""
import collections
import hashlib
import json
from pathlib import Path
import struct
import sys
import tarfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO / 'src/unauthorized_channels'))
sys.path.insert(0, str(REPO / 'scripts'))
from unauthorized_channels.backend_recipe_store import computation_key
from rgec_backend_probe import packet_info, key, queue_signature
from rgec_native_effect_probe import signature


def sha(data): return hashlib.sha256(data).hexdigest()
def load(path): return json.loads(path.read_text(encoding='utf-8'))


def state(data):
    offset = 0
    def number():
        nonlocal offset
        assert len(data) - offset >= 8
        value = struct.unpack_from('<Q', data, offset)[0]; offset += 8
        return value
    def field():
        nonlocal offset
        length = number(); value = data[offset:offset + length]; offset += length
        assert len(value) == length
        return value
    args = [field() for _ in range(number())]; bitcode = field()
    count = number(); number(); files = []
    for _ in range(1, count):
        number(); file = bool(number()); files.append(file)
        number(); number()
        if file: field(); field()
        else: number(); number()
    assert data[offset:offset + 6] == b'RGECS3'; offset += 6
    field(); number()
    for file in files:
        number()
        if file: number(); number()
    if number():
        for _ in range(number()): field()
        for _ in range(number()):
            number()
            for _ in range(number() * 5): number()
    number(); number()
    for _ in range(number()):
        field()
        if number(): number()
    prefix = data[:offset]
    assert data[offset:offset + 6] == b'RGECR1'; offset += 6
    reads = []
    for _ in range(number()):
        reads.append({'path': field().decode(), 'size': number(), 'terminated': number(),
                      'volatile': number(), 'identifier': field().decode(), 'contents': field()})
    assert offset == len(data)
    return args, bitcode, prefix, reads


def symbols(data):
    assert data[:6] == b'\x7fELF\x02\x01'
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data); assert header[2] == 62
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, header[6] + i * header[11]) for i in range(header[12])]
    result = set()
    for section in sections:
        if section[1] != 2: continue
        strings = sections[section[6]]; names = data[strings[4]:strings[4] + strings[5]]
        for at in range(section[4], section[4] + section[5], section[9]):
            name, info, _, index, _, _ = struct.unpack_from('<IBBHQQ', data, at)
            if index and info >> 4 in (1, 2): result.add(names[name:names.index(b'\0', name)].decode())
    return result


def audit(root):
    manifest = load(root / 'evidence.json'); counts = collections.Counter()
    for path, expected in manifest['source_sha256'].items():
        assert sha((root / Path(path).name).read_bytes()) == expected
        counts['frozen_source_snapshots'] += 1
    phases = {}
    for row in manifest['sandboxes']:
        assert row['returncode'] == 0 and row['cleanup_returncode'] == 137
        folder = root / row['phase']; phases[row['phase']] = load(folder / 'evidence.json')
        archive = folder / 'raw.tar.gz'; assert sha(archive.read_bytes()) == row['raw_archive_sha256']
        with tarfile.open(archive) as stream:
            for member in stream:
                assert member.isfile() and member.name == 'raw/' + Path(member.name).name
                assert stream.extractfile(member).read() == (folder / Path(member.name).name).read_bytes()
                counts['archive_members'] += 1
        counts['archives'] += 1
    assert len({json.dumps(p['tool_sha256'], sort_keys=True) for p in phases.values()}) == 1
    tools = phases['capture']['tool_sha256']
    for remote, filename in {'/rgec-backend.cpp': 'clang_backend_continuation.cpp',
        '/clang_residual_backend.h': 'clang_residual_backend.h',
        '/clang_backend_read_state.h': 'clang_backend_read_state.h'}.items():
        assert sha((root / filename).read_bytes()) == tools[remote]
    def checked(phase, filename, expected):
        data = (root / phase / filename).read_bytes(); assert sha(data) == expected, filename
        counts['recorded_raw_hashes'] += 1
        return data
    def observation(phase, row):
        for k, suffix in {'stdout_sha256': '.stdout', 'stderr_sha256': '.stderr',
            'control_sha256': '.control', 'held_fd_content_sha256': '.held.o', 'object_sha256': '.object.o'}.items():
            if row.get(k) is not None: checked(phase, row['case'] + suffix, row[k])
        counts['native_observations'] += 1
    by_name = {r['name']: r for r in phases['capture']['cases']}; captured = {}
    for name, row in by_name.items():
        source = checked('capture', row['source'] + '.original', row['source_sha256'])
        assert source == (REPO / 'runs/rgec-modal-authority-cold-warm-2026-10-04-v3' / (row['source'] + '.original')).read_bytes()
        for role in ('native', 'record'): observation('capture', row[role])
        assert all(row['native'][k] == row['record'][k] for k in
            ('returncode', 'stdout_sha256', 'stderr_sha256', 'object_sha256'))
        bound = checked('capture', name + '.key', row['record']['key_sha256'])
        captured[name] = state(bound)
        reads = captured[name][3]; assert len(reads) == len(row['maps'])
        for read, (path, filename) in zip(reads, row['maps']):
            assert read['path'] == read['identifier'] == path
            assert (read['size'], read['terminated'], read['volatile']) == (2**64 - 1, 1, 0)
            assert read['contents'] == (root / 'capture' / filename).read_bytes()
            counts['bound_native_reads'] += 1
        target = 'rgec_actual_map_' + ('C' if row['version'] == 'chain' else row['version'])
        actual = symbols((root / 'capture' / (row['native']['case'] + '.object.o')).read_bytes())
        assert target in actual and row['symbol'] not in actual
    for source in sorted({row['source'] for row in by_name.values()}):
        a, b = (captured[source + '-map-' + v] for v in ('A', 'B'))
        assert a[:3] == b[:3]  # argv, genuine captured IR and all pre-read state agree.
        assert a[3][0]['contents'] != b[3][0]['contents']
    producer = phases['producer']; assert len(producer['cases']) == len(by_name) == 9
    for row in producer['map_open_controls']:
        assert row['returncode'] != 0
        for k, suffix in {'stdout_sha256': '.stdout', 'stderr_sha256': '.stderr'}.items():
            data = checked('producer', Path(row['path']).name + '.open' + suffix, row[k])
            if suffix == '.stderr': assert b'PermissionError' in data
    for row in producer['cases']:
        name = row['name']; original = by_name[name]
        bound = checked('producer', name + '.key', row['query_sha256'])
        assert bound == (root / 'capture' / (name + '.key')).read_bytes()
        packet = checked('producer', name + '.packet', row['packet_sha256'])
        delivery = checked('producer', name + '.compact.packet', row['compact_packet_sha256'])
        assert packet_info(packet) == row['info'] and row['info']['reusable']
        assert packet_info(delivery) == row['compact_info']
        size = struct.unpack_from('<Q', packet, 6)[0]
        assert packet[:6] == b'RGECB2' and packet[14:14 + size] == bound
        assert delivery == b'RGECB3' + packet[14 + size:]
        length = struct.unpack_from('<Q', packet, 14 + size)[0]
        assert packet[22 + size:22 + size + length] == computation_key(bound)
        assert (row['returncode'], row['object_sha256']) == (original['native']['returncode'], original['native']['object_sha256'])
        checked('producer', name + '.object.o', row['object_sha256'])
        checked('producer', name + '.stderr', row['stderr_sha256'])
        fresh = row['fresh_frontend']; assert fresh['returncode'] != 0 and not fresh['packet_emitted']
        assert not checked('producer', name + '.fresh.control', fresh['control_sha256'])
        checked('producer', name + '.fresh.stderr', fresh['stderr_sha256'])
        counts['sealed_read_native_producers'] += 1
    matches = collections.Counter(); routes = collections.Counter()
    for row in phases['replay']['cases']:
        native, replay = row['native'], row['replay']
        for trace in (native, replay): observation('replay', trace)
        derived = {'status_and_streams_match': all(native[k] == replay[k] for k in
            ('returncode', 'stdout_sha256', 'stderr_sha256')),
            'object_bytes_match': native['object_sha256'] == replay['object_sha256'],
            'structural_effects_match': signature(native) == signature(replay),
            'queued_event_roles_match': queue_signature(native['events']) == queue_signature(replay['events'])}
        for k, value in derived.items(): assert row[k] == value; matches[k] += value
        routes[row['route']] += 1
        bound, receipt = key((root / 'replay' / (replay['case'] + '.control')).read_bytes())
        if row['route'] == 'native-read-failure-before-query': assert not bound
        else:
            assert receipt == (b'RGECH1' if row['route'] == 'own-read-bound-hit' else b'RGECF1')
            name = row['name'].removesuffix('-old-A')
            assert bound == (root / 'capture' / (name + '.key')).read_bytes()
    assert dict(matches) == phases['replay']['matching_pairs']
    result = {'root': str(root), 'manifest_sha256': sha((root / 'evidence.json').read_bytes()),
        'tool_sha256': tools, 'counts': dict(counts), 'routes': dict(routes), 'matching_pairs': dict(matches),
        'recipient_pairs': len(phases['replay']['cases']), 'protected_input_files': len(producer['protected_input_files']),
        'complete_closure_certified': False, 'adaptive_noninterference_proved': False}
    (root / 'independent-read-audit.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    for argument in sys.argv[1:]: audit(Path(argument))
