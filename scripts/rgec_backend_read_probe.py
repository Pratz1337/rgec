"""Native symbol-map read capture and replay across separate Modal workers."""
import json
import os
import struct
import sys

sys.path.insert(0, '/')
import rgec_residual_probe as residual
from rgec_backend_probe import ROOT, packet_info, reset, run, queue_signature
from rgec_native_effect_probe import FLAGS, sha, signature

MAP = ROOT + '/rewrite-map.yaml'
SECOND = ROOT + '/rewrite-second.yaml'


def compact(packet):
    assert packet[:6] == b'RGECB2'
    size = struct.unpack_from('<Q', packet, 6)[0]
    return b'RGECB3' + packet[14 + size:]


def maps(case):
    for path, filename in case['maps']:
        with open(path, 'wb') as stream:
            stream.write(open('/transfer-capture/' + filename, 'rb').read())
        os.chmod(path, 0o644)


def pair(case, prior, packet, result, route):
    native = residual.request(case, 'native', prior)
    replay = residual.request(case, 'replay', prior, packet)
    row = {'name': case['name'], 'route': route, 'native': native, 'replay': replay,
        'status_and_streams_match': all(native[k] == replay[k] for k in
            ('returncode', 'stdout_sha256', 'stderr_sha256')),
        'object_bytes_match': native['object_sha256'] == replay['object_sha256'],
        'structural_effects_match': signature(native) == signature(replay),
        'queued_event_roles_match': queue_signature(native['events']) == queue_signature(replay['events'])}
    result['cases'].append(row)
    print(case['name'], route, native['returncode'], replay['returncode'], replay['receipt'],
          row['status_and_streams_match'], row['object_bytes_match'], flush=True)
    return row


def main(phase):
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    result = {'phase': phase, 'cases': [], 'complete_closure_certified': False,
        'adaptive_noninterference_proved': False,
        'scope': 'Unchanged authentic project sources and genuine native map parser/pass pipeline; ordered successful read bytes are bound into the residual key.'}
    for path in ('/usr/local/bin/clang', '/rgec-backend', '/rgec-backend.cpp',
                 '/clang_residual_backend.h', '/clang_backend_read_state.h'):
        result.setdefault('tool_sha256', {})[path] = sha(open(path, 'rb').read())
    try:
        if phase == 'capture':
            status, out, error = run(['/usr/local/bin/clang'] + FLAGS +
                ['-fPIC', '-c', 'deflate.c', '-o', ROOT + '/prior.o'], '/src/zlib')
            assert status == 0, error
            prior = open(ROOT + '/prior.o', 'rb').read()
            for path in ('/src/zlib/adler32.c', '/src/zlib/deflate.c', '/src/libfuzzer/FuzzerUtil.cpp'):
                original = open(path, 'rb').read()
                cwd, source = os.path.dirname(path), os.path.basename(path)
                case = {'name': source + '-unmapped', 'source': source, 'source_path': path,
                    'cwd': cwd, 'source_sha256': residual.save(source + '.original', original),
                    'compiler': '/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang',
                    'flags': FLAGS + (['-stdlib=libc++', '-std=c++11'] if source.endswith('.cpp') else ['-fPIC'])}
                baseline = residual.request(case, 'native', prior)
                assert baseline['returncode'] == 0
                status, symbols, error = run(['/usr/bin/nm', '-g', '--defined-only',
                    ROOT + '/action-' + source + '/action.o'], cwd)
                assert status == 0, error
                residual.save(source + '-unmapped.nm', symbols)
                functions = [line.split()[-1] for line in symbols.decode().splitlines()
                    if len(line.split()) == 3 and line.split()[1] == 'T']
                symbol = ('adler32' if source == 'adler32.c' else 'deflate' if source == 'deflate.c'
                    else next(name for name in functions if 'SimpleFastHash' in name))
                assert symbol in functions
                for version in ('A', 'B', 'chain'):
                    entries = [(MAP, symbol, 'rgec_actual_map_' + ('A' if version == 'chain' else version))]
                    if version == 'chain': entries.append((SECOND, 'rgec_actual_map_A', 'rgec_actual_map_C'))
                    row = dict(case, name=source + '-map-' + version, version=version, symbol=symbol,
                               flags=list(case['flags']), maps=[])
                    for index, (mapping, src, target) in enumerate(entries):
                        data = ('function: { source: "' + src + '", target: "' + target + '" }\n').encode()
                        with open(mapping, 'wb') as stream: stream.write(data)
                        os.chmod(mapping, 0o644)
                        filename = row['name'] + '-' + str(index) + '.yaml'
                        residual.save(filename, data)
                        row['maps'].append((mapping, filename))
                        row['flags'] += ['-frewrite-map-file', mapping]
                    row['native'] = residual.request(row, 'native', prior)
                    row['record'] = residual.request(row, 'record', prior)
                    row['native_record_match'] = all(row['native'][k] == row['record'][k]
                        for k in ('returncode', 'stdout_sha256', 'stderr_sha256', 'object_sha256'))
                    result['cases'].append(row)
                    print(row['name'], 'captured native reads', row['native_record_match'], flush=True)
                    assert row['native_record_match'] and row['record'].get('info', {}).get('reusable'), row
                assert open(path, 'rb').read() == original
        else:
            capture = json.load(open('/transfer-capture/evidence.json'))
            prior = open('/transfer-capture/prior.o', 'rb').read()
            if phase == 'producer':
                protected = set()
                for case in capture['cases']:
                    bound = open('/transfer-capture/' + case['name'] + '.key', 'rb').read()
                    for name, _ in residual.state_input(bound)['files']:
                        path = os.path.abspath(os.path.join(case['cwd'], name))
                        if not name.startswith('<') and os.path.isfile(path): protected.add(os.path.realpath(path))
                    maps(case)
                    protected.update(path for path, _ in case['maps'])
                for path in protected: os.chmod(path, 0)
                result['protected_input_files'] = sorted(protected)
                result['map_open_controls'] = []
                for mapping in sorted({path for case in capture['cases'] for path, _ in case['maps']}):
                    status, out, error = run(['/usr/bin/python3', '-I', '-c',
                        'import sys; open(sys.argv[1], "rb").read()', mapping], '/src/zlib')
                    result['map_open_controls'].append({'path': mapping, 'returncode': status,
                        'stdout_sha256': residual.save(os.path.basename(mapping) + '.open.stdout', out),
                        'stderr_sha256': residual.save(os.path.basename(mapping) + '.open.stderr', error)})
                    assert status != 0 and b'PermissionError' in error
                for case in capture['cases']:
                    name = case['name']; bound = open('/transfer-capture/' + name + '.key', 'rb').read()
                    args = residual.state_input(bound)['arguments']
                    reset(ROOT + '/action-' + case['source'], 'hardlink', prior)
                    status, out, error = run(['/rgec-backend', '-cc1'] + args, case['cwd'], 'record')
                    fresh = {'returncode': status, 'packet_emitted': bool(out),
                        'control_sha256': residual.save(name + '.fresh.control', out),
                        'stderr_sha256': residual.save(name + '.fresh.stderr', error)}
                    reset(ROOT + '/action-' + case['source'], 'hardlink', prior)
                    status, packet, error = run(['/rgec-backend', '--rgec-produce-parametric'], case['cwd'], None, bound)
                    row = {'name': name, 'returncode': status, 'fresh_frontend': fresh,
                        'query_sha256': residual.save(name + '.key', bound),
                        'packet_sha256': residual.save(name + '.packet', packet),
                        'stderr_sha256': residual.save(name + '.stderr', error)}
                    result['cases'].append(row)
                    info = packet_info(packet); row['info'] = info
                    delivery = compact(packet); row['compact_info'] = packet_info(delivery)
                    row['compact_packet_sha256'] = residual.save(name + '.compact.packet', delivery)
                    output = ROOT + '/action-' + case['source'] + '/action.o'
                    row['object_sha256'] = residual.save(name + '.object.o', open(output, 'rb').read()) if os.path.isfile(output) else None
                    row['native_status_object_match'] = (status, row['object_sha256']) == (case['native']['returncode'], case['native']['object_sha256'])
                    print(name, 'closed producer', status, row['native_status_object_match'], flush=True)
                    assert fresh['returncode'] != 0 and not fresh['packet_emitted']
                    assert info['reusable'] and info['key_sha256'] == sha(bound) and row['native_status_object_match'], row
            else:
                for case in capture['cases']:
                    assert sha(open(case['source_path'], 'rb').read()) == case['source_sha256']
                    maps(case)
                    own = open('/transfer-producer/' + case['name'] + '.compact.packet', 'rb').read()
                    row = pair(case, prior, own, result, 'own-read-bound-hit')
                    assert row['replay']['receipt'] == 'RGECH1'
                    if case['version'] != 'B': continue
                    old = open('/transfer-producer/' + case['source'] + '-map-A.compact.packet', 'rb').read()
                    row = pair(dict(case, name=case['name'] + '-old-A'), prior, old, result, 'changed-read-recompute')
                    assert row['replay']['receipt'] == 'RGECF1'
                    for fault in ('missing', 'unreadable', 'invalid'):
                        maps(case)
                        if fault == 'missing': os.unlink(MAP)
                        elif fault == 'unreadable': os.chmod(MAP, 0)
                        else:
                            with open(MAP, 'wb') as stream: stream.write(b'function: { source: "[", target: "x" }\n')
                        row = pair(dict(case, name=case['name'] + '-' + fault), prior, old, result, 'native-read-failure-before-query')
                        row['query_emitted'] = bool(row['replay']['key_sha256'])
                        assert not row['query_emitted'], row
                    maps(case)
                result['matching_pairs'] = {k: sum(row[k] for row in result['cases']) for k in
                    ('status_and_streams_match', 'object_bytes_match', 'structural_effects_match', 'queued_event_roles_match')}
    finally:
        with open(ROOT + '/evidence.json', 'w') as stream: json.dump(result, stream, indent=2)


if __name__ == '__main__': main(sys.argv[1])
