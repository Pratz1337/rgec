"""Compare genuine full/sliced generated-function packets on native Modal jobs."""
import json
import os
import random
import resource
import struct
import subprocess
import sys
import time

sys.path.insert(0, '/')
import rgec_residual_probe as residual
from modal_recipient_entry import ENV, drop
from rgec_backend_probe import ROOT, key, packet_info, reset, run, watch, queue_signature
from rgec_native_effect_probe import FLAGS, observe, sha, signature
from rgec_native_event_probe import events

MAP = ROOT + '/rewrite-map.yaml'
TOOLS = ('/usr/local/bin/clang', '/rgec-backend-full', '/rgec-backend',
         '/rgec-backend.cpp', '/clang_residual_backend-full.h',
         '/clang_residual_backend.h', '/clang_backend_read_state.h',
         '/usr/local/lib/libLLVMTransformUtils.a', '/usr/local/lib/libLLVMCore.a',
         '/usr/local/lib/libclangCodeGen.a')


def source(case, prefix, policy):
    original = open('/transfer-capture/' + case['source'] + '.original', 'rb').read()
    contents = ('#pragma clang diagnostic ' + prefix + ' "-W#warnings"\n'
        '#warning RGEC real frontend history one\n'
        '#warning RGEC real frontend history two\n'
        '#pragma clang diagnostic ' + policy + ' "-Wframe-larger-than="\n').encode() + original
    with open(case['source_path'], 'wb') as stream: stream.write(contents)
    os.utime(case['source_path'], (1641013200, 1641013200))
    with open(MAP, 'wb') as stream: stream.write(case['map'].encode())
    os.chmod(MAP, 0o644)
    return contents


def compact(packet):
    assert packet[:6] == b'RGECB2'
    size = struct.unpack_from('<Q', packet, 6)[0]
    return b'RGECB3' + packet[14 + size:]


def operations(packet):
    offset = [6]
    def number():
        value = struct.unpack_from('<Q', packet, offset[0])[0]; offset[0] += 8
        return value
    def field():
        length = number(); value = packet[offset[0]:offset[0] + length]; offset[0] += length
        assert len(value) == length
        return value
    field()
    if packet[:6] == b'RGECB2': field()
    number(); frames = number(); assert frames == 0
    result = []
    for _ in range(number()): result.append((number(), number(), field()))
    assert offset[0] == len(packet)
    return result


def inspect(packet, label):
    projection = []; snapshots = []
    for kind, position, data in operations(packet):
        if kind != 6:
            projection.append((kind, position, sha(data))); continue
        offset = [0]
        def number():
            value = struct.unpack_from('<Q', data, offset[0])[0]; offset[0] += 8
            return value
        def field():
            length = number(); value = data[offset[0]:offset[0] + length]; offset[0] += length
            return value
        name = field().decode(); size, limit = number(), number()
        identifier, bitcode = field(), field(); assert offset[0] == len(data)
        projection.append((kind, position, name, size, limit, sha(identifier)))
        filename = label + '-generated-' + str(len(snapshots))
        residual.save(filename + '.bc', bitcode)
        status, ir, error = run(['/usr/local/bin/llvm-dis', ROOT + '/' + filename + '.bc', '-o', '-'], '/src/zlib')
        assert status == 0, error
        residual.save(filename + '.ll', ir)
        status, out, error = run(['/usr/local/bin/opt', '-verify', '-disable-output',
                                ROOT + '/' + filename + '.bc'], '/src/zlib')
        residual.save(filename + '.verify.stdout', out); residual.save(filename + '.verify.stderr', error)
        assert status == 0, error
        definitions = [line for line in ir.decode().splitlines() if line.startswith('define ')]
        assert any('@' + name + '(' in line or '@"' + name + '"(' in line for line in definitions), name
        snapshots.append({'name': name, 'size': size, 'limit': limit, 'identifier_sha256': sha(identifier),
                          'bitcode_bytes': len(bitcode), 'bitcode_sha256': sha(bitcode),
                          'definition_count': len(definitions), 'ir_sha256': sha(ir), 'verify_returncode': status})
    return {'projection': projection, 'generated_snapshots': snapshots, 'packet_bytes': len(packet)}


def request(case, mode, prior, packet, label):
    folder = ROOT + '/action-' + case['source']; output = reset(folder, 'hardlink', prior)
    paths = [output, folder + '/alias.o', folder + '/target.o']
    row = {'label': label, 'mode': mode, 'paths': paths, 'before': {p: observe(p) for p in paths}}
    held = os.open(output, os.O_RDONLY); fd = watch(folder)
    env = dict(ENV)
    if mode != 'native': env['RGEC_BACKEND_MODE'] = 'replay'
    backend = '/usr/local/bin/clang' if mode == 'native' else '/rgec-backend-full' if mode == 'full' else '/rgec-backend'
    argv = [backend, '-cc1'] + case['arguments']; row['argv'] = argv
    child_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    self_before = resource.getrusage(resource.RUSAGE_SELF); start = time.monotonic()
    process = subprocess.Popen(argv, cwd=case['cwd'], env=env, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=drop, close_fds=True)
    control, diagnostic = process.communicate(packet, timeout=180)
    row['helper_wall_seconds'] = time.monotonic() - start
    child_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    self_after = resource.getrusage(resource.RUSAGE_SELF)
    row['child_cpu_seconds'] = (child_after.ru_utime + child_after.ru_stime) - (child_before.ru_utime + child_before.ru_stime)
    row['service_cpu_seconds'] = (self_after.ru_utime + self_after.ru_stime) - (self_before.ru_utime + self_before.ru_stime)
    bound, receipt = key(control) if mode != 'native' else (None, b'')
    row.update(returncode=process.returncode, receipt=receipt.decode(),
        query_sha256=residual.save(label + '.query', bound) if bound else None,
        stdout_sha256=residual.save(label + '.stdout', control if mode == 'native' else b''),
        stderr_sha256=residual.save(label + '.stderr', diagnostic),
        control_sha256=residual.save(label + '.control', control),
        held_fd_content_sha256=residual.save(label + '.held', os.read(held, 10000000)),
        after={p: observe(p) for p in paths}, events=events(fd),
        directory_entries_after=sorted(os.listdir(folder)))
    os.close(held)
    row['object_sha256'] = residual.save(label + '.object.o', open(output, 'rb').read()) if os.path.isfile(output) else None
    return row


def main(phase):
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    result = {'phase': phase, 'cases': [], 'rows': [], 'tool_sha256': {p: sha(open(p, 'rb').read()) for p in TOOLS},
        'complete_closure_certified': False, 'adaptive_noninterference_proved': False,
        'scope': 'Unchanged actual project function bodies, native maps and diagnostic directives. Same native compiler/static libraries; real full versus CloneModule-sliced generated definitions.'}
    def persist(): residual.save('evidence.json', (json.dumps(result, indent=2) + '\n').encode())
    try:
        if phase == 'capture':
            status, out, error = run(['/usr/local/bin/clang'] + FLAGS + ['-fPIC', '-c', 'deflate.c', '-o', ROOT + '/prior.o'], '/src/zlib')
            assert status == 0, error
            prior = open(ROOT + '/prior.o', 'rb').read()
            for path, symbol in (('/src/zlib/adler32.c', 'adler32'), ('/src/zlib/deflate.c', 'deflate'),
                                 ('/src/libfuzzer/FuzzerUtil.cpp', '_ZN6fuzzer14SimpleFastHashEPKhm')):
                original = open(path, 'rb').read(); original_stat = os.stat(path)
                source_name, cwd = os.path.basename(path), os.path.dirname(path)
                residual.save(source_name + '.original', original)
                try:
                    contents = b'#pragma clang diagnostic ignored "-W#warnings"\n#warning RGEC real frontend history one\n#warning RGEC real frontend history two\n#pragma clang diagnostic warning "-Wframe-larger-than="\n' + original
                    with open(path, 'wb') as stream: stream.write(contents)
                    os.utime(path, (1641013200, 1641013200)); residual.save(source_name + '.captured.source', contents)
                    mapping = 'function: { source: "' + symbol + '", target: "rgec_slice_' + symbol + '" }\n'
                    with open(MAP, 'wb') as stream: stream.write(mapping.encode())
                    os.chmod(MAP, 0o644)
                    for limit in (1, 0):
                        case = {'name': source_name + '-limit-' + str(limit), 'source': source_name,
                            'source_path': path, 'cwd': cwd, 'map': mapping, 'error_limit': limit,
                            'original_sha256': sha(original), 'captured_source_sha256': sha(contents),
                            'compiler': '/usr/local/bin/clang++' if source_name.endswith('.cpp') else '/usr/local/bin/clang',
                            'flags': FLAGS + (['-stdlib=libc++', '-std=c++11'] if source_name.endswith('.cpp') else ['-fPIC'])
                                + ['-Wframe-larger-than=1', '-ferror-limit=' + str(limit), '-frewrite-map-file', MAP]}
                        native = residual.request(dict(case, name=case['name'] + '-native'), 'native', prior)
                        for mode, backend in (('full', '/rgec-backend-full'), ('sliced', '/rgec-backend')):
                            os.unlink('/rgec-driver/clang-7'); os.symlink(backend, '/rgec-driver/clang-7')
                            recorded = residual.request(dict(case, name=case['name'] + '-' + mode), 'record', prior)
                            case[mode] = recorded
                            assert all(recorded[k] == native[k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256', 'object_sha256')), case
                            assert recorded['info']['reusable'], case
                        case['native'] = native
                        bound = open(ROOT + '/' + case['name'] + '-full.key', 'rb').read()
                        assert bound == open(ROOT + '/' + case['name'] + '-sliced.key', 'rb').read()
                        case['arguments'] = residual.state_input(bound)['arguments']
                        result['cases'].append(case); persist()
                        print(case['name'], 'genuine full/sliced captures match native', flush=True)
                finally:
                    with open(path, 'wb') as stream: stream.write(original)
                    os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        else:
            capture = json.load(open('/transfer-capture/evidence.json'))
            prior = open('/transfer-capture/prior.o', 'rb').read()
            if phase == 'producer':
                protected = set()
                for case in capture['cases']:
                    bound = open('/transfer-capture/' + case['name'] + '-full.key', 'rb').read()
                    for name, _ in residual.state_input(bound)['files']:
                        path = os.path.realpath(os.path.abspath(os.path.join(case['cwd'], name)))
                        if not name.startswith('<') and os.path.isfile(path): protected.add(path)
                with open(MAP, 'wb') as stream: stream.write(capture['cases'][0]['map'].encode())
                protected.add(MAP)
                for path in protected: os.chmod(path, 0)
                result['protected_input_files'] = sorted(protected)
                status, out, error = run(['/usr/bin/python3', '-I', '-c',
                    'import sys; open(sys.argv[1], "rb").read()', MAP], '/src/zlib')
                result['map_open_returncode'] = status
                residual.save('map-open.stdout', out); residual.save('map-open.stderr', error)
                assert status != 0 and b'PermissionError' in error
                for case in capture['cases']:
                    bound = open('/transfer-capture/' + case['name'] + '-full.key', 'rb').read()
                    row = {'name': case['name']}; result['cases'].append(row)
                    for mode, backend in (('full', '/rgec-backend-full'), ('sliced', '/rgec-backend')):
                        label = case['name'] + '-' + mode
                        reset(ROOT + '/action-' + case['source'], 'hardlink', prior)
                        status, out, error = run([backend, '-cc1'] + case['arguments'], case['cwd'], 'record')
                        residual.save(label + '.fresh.control', out); residual.save(label + '.fresh.stderr', error)
                        assert status != 0 and not out
                        fresh_status = status
                        reset(ROOT + '/action-' + case['source'], 'hardlink', prior)
                        status, packet, error = run([backend, '--rgec-produce-parametric'], case['cwd'], None, bound)
                        residual.save(label + '.packet', packet); residual.save(label + '.stderr', error)
                        delivery = compact(packet); residual.save(label + '.compact.packet', delivery)
                        output = ROOT + '/action-' + case['source'] + '/action.o'
                        object_hash = residual.save(label + '.object.o', open(output, 'rb').read()) if os.path.isfile(output) else None
                        info = packet_info(packet)
                        assert info['reusable'] and info['key_sha256'] == sha(bound)
                        assert (status, object_hash) == (case['native']['returncode'], case['native']['object_sha256'])
                        row[mode] = dict(inspect(delivery, label), returncode=status, object_sha256=object_hash,
                            packet_sha256=sha(packet), delivery_sha256=sha(delivery), key_sha256=sha(bound),
                            computation_key_sha256=info['computation_key_sha256'], fresh_frontend_returncode=fresh_status)
                    assert row['full']['projection'] == row['sliced']['projection']
                    assert row['full']['computation_key_sha256'] == row['sliced']['computation_key_sha256']
                    assert row['full']['generated_snapshots'] and row['sliced']['generated_snapshots']
                    print(case['name'], 'sealed actual producers', row['full']['packet_bytes'], row['sliced']['packet_bytes'], flush=True)
                    persist()
            else:
                rng = random.Random(6531)
                for case in capture['cases']:
                    original = open(case['source_path'], 'rb').read(); original_stat = os.stat(case['source_path'])
                    assert sha(original) == case['original_sha256']
                    try:
                        for block in range(2):
                            conditions = [(prefix, policy, mode) for prefix in ('ignored', 'warning')
                                for policy in ('ignored', 'warning', 'error') for mode in ('native', 'full', 'sliced')]
                            rng.shuffle(conditions)
                            for prefix, policy, mode in conditions:
                                contents = source(case, prefix, policy)
                                packet = open('/transfer-producer/' + case['name'] + '-' + mode + '.compact.packet', 'rb').read() if mode != 'native' else None
                                label = 'action-' + str(len(result['rows'])).zfill(3)
                                row = request(case, mode, prior, packet, label)
                                row.update(name=case['name'], block=block, prefix=prefix, policy=policy, source_sha256=sha(contents))
                                result['rows'].append(row); persist()
                                if mode != 'native': assert row['receipt'] == 'RGECH1', row
                            for prefix in ('ignored', 'warning'):
                                for policy in ('ignored', 'warning', 'error'):
                                    group = [row for row in result['rows'] if row['name'] == case['name'] and row['block'] == block and row['prefix'] == prefix and row['policy'] == policy]
                                    native = next(row for row in group if row['mode'] == 'native')
                                    for row in group:
                                        row['status_and_streams_match'] = all(row[k] == native[k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256'))
                                        row['object_bytes_match'] = row['object_sha256'] == native['object_sha256']
                                        row['structural_effects_match'] = signature(row) == signature(native)
                                        row['event_roles_match'] = queue_signature(row['events']) == queue_signature(native['events'])
                                    # Preserve real counterexamples instead of suppressing collection.
                            print(case['name'], 'real diagnostic/error-limit block', block, flush=True); persist()
                    finally:
                        with open(case['source_path'], 'wb') as stream: stream.write(original)
                        os.utime(case['source_path'], ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    finally: persist()


if __name__ == '__main__': main(sys.argv[1])
