"""Real failure-repair and dependency checks in the pinned Modal compiler image."""
import json
import os
import struct
import sys

sys.path.insert(0, '/')
from rgec_backend_probe import ROOT, driver, key, packet_info, reset, run, watch, queue_signature
from rgec_native_effect_probe import FLAGS, observe, sha, signature
from rgec_native_event_probe import events


def save(name, extension, data):
    with open(ROOT + '/' + name + '.' + extension, 'wb') as stream:
        stream.write(data)
    return sha(data)


def input_state(bound):
    offset = [0]
    def number():
        value = struct.unpack_from('<Q', bound, offset[0])[0]
        offset[0] += 8
        return value
    def field():
        length = number()
        value = bound[offset[0]:offset[0] + length]
        offset[0] += length
        return value
    arguments = [field() for _ in range(number())]
    bitcode = field()
    count, next_offset = number(), number()
    files = []
    for _ in range(1, count):
        number()
        if number():
            number(); number()
            files.append((field().decode(), field()))
        else:
            number(); number(); number(); number()
    assert offset[0] == len(bound)
    return {'bitcode_sha256': sha(bitcode), 'files': files,
            'argument_count': len(arguments), 'next_source_offset': next_offset}


def compare(name, source, cwd, flags, packet, kind, prior, expected_receipt, expected_status):
    pair = []
    folder = ROOT + '/action-' + source
    compiler = '/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang'
    for mode in ('native', 'replay'):
        output = reset(folder, kind, prior)
        argv = [compiler] + flags + ['-c', source, '-o', output]
        if mode == 'replay':
            argv = driver(argv, cwd)
        paths = [output, folder + '/alias.o', folder + '/target.o']
        before = {path: observe(path) for path in paths}
        held = os.open(output, os.O_RDONLY) if kind in ('regular', 'hardlink') else None
        fd = watch(folder)
        status, control, diagnostic = run(argv, cwd, 'replay' if mode == 'replay' else None,
                                          packet if mode == 'replay' else None)
        queued = events(fd)
        bound, receipt = key(control) if mode == 'replay' else (None, control)
        label = name + '-' + kind + '-' + mode
        row = {'case': label, 'mode': mode, 'returncode': status, 'paths': paths,
               'before': before, 'after': {path: observe(path) for path in paths},
               'directory_entries_after': sorted(os.listdir(folder)), 'events': queued,
               'receipt': receipt.decode(), 'key_sha256': sha(bound) if bound else None,
               'stdout_sha256': save(label, 'stdout', b'' if mode == 'replay' else control),
               'stderr_sha256': save(label, 'stderr', diagnostic),
               'control_sha256': save(label, 'control', control), 'retained_objects': {}}
        if bound:
            row['input_state'] = {k: v for k, v in input_state(bound).items() if k != 'files'}
        if held is not None:
            contents = os.read(held, 10000000)
            row['held_fd_content_sha256'] = save(label, 'held.o', contents)
            os.close(held)
        for role, path in zip(('output', 'alias', 'target'), paths):
            if os.path.isfile(path):
                with open(path, 'rb') as stream:
                    row['retained_objects'][role] = save(label, role + '.o', stream.read())
        pair.append(row)
    native, replay = pair
    replay['status_and_streams_match'] = (native['returncode'], native['stdout_sha256'], native['stderr_sha256']) == \
                                       (replay['returncode'], replay['stdout_sha256'], replay['stderr_sha256'])
    replay['structural_effects_match'] = signature(native) == signature(replay)
    replay['queued_event_roles_match'] = queue_signature(native['events']) == queue_signature(replay['events'])
    assert native['returncode'] == replay['returncode'] == expected_status, pair
    assert replay['receipt'] == expected_receipt, replay
    assert all(replay[k] for k in ('status_and_streams_match', 'structural_effects_match', 'queued_event_roles_match')), pair
    print(label, expected_receipt or 'no query', 'matched', flush=True)
    return pair


def main():
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    evidence = {'rows': [], 'primes': [], 'header_checks': [], 'complete_closure_certified': False,
                'authenticated_origin_established': False, 'adaptive_noninterference_proved': False}
    for path in ('/usr/local/bin/clang', '/rgec-backend', '/rgec-backend.cpp'):
        with open(path, 'rb') as stream:
            evidence.setdefault('native_tool_sha256', {})[path] = sha(stream.read())
    code, output, error = run(['/usr/local/bin/clang'] + FLAGS + ['-fPIC', '-c', 'deflate.c', '-o', ROOT + '/prior.o'], '/src/zlib')
    assert code == 0, error
    prior = open(ROOT + '/prior.o', 'rb').read()
    for source_path in ('/src/zlib/adler32.c', '/src/zlib/deflate.c', '/src/libfuzzer/FuzzerUtil.cpp'):
        cwd, source = os.path.dirname(source_path), os.path.basename(source_path)
        original = open(source_path, 'rb').read()
        original_stat = os.stat(source_path)
        header_path = None
        save(source, 'original', original)
        flags = FLAGS + (['-stdlib=libc++', '-std=c++11'] if source.endswith('.cpp') else ['-fPIC'])
        compiler = '/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang'
        try:
            packets = {}
            for variant in ('pristine', 'backend-error'):
                suffix = b'' if variant == 'pristine' else b'\nvoid rgec_actual_backend_error(void) { __asm__("rgec_invalid_instruction"); }\n'
                open(source_path, 'wb').write(original + suffix)
                save(source + '-' + variant, 'source', original + suffix)
                output = reset(ROOT + '/action-' + source, 'regular', prior)
                argv = driver([compiler] + flags + ['-c', source, '-o', output], cwd)
                code, packet, diagnostic = run(argv, cwd, 'record')
                info = packet_info(packet)
                assert info['reusable'] and code == (1 if suffix else 0), diagnostic
                evidence['primes'].append({'case': source + '-' + variant, 'returncode': code,
                    'packet_sha256': save(source + '-' + variant, 'packet', packet),
                    'stderr_sha256': save(source + '-' + variant, 'prime.stderr', diagnostic),
                    'key_sha256': info['key_sha256']})
                packets[variant] = packet
            open(source_path, 'wb').write(original)
            pristine = packets['pristine']
            for kind in ('regular', 'hardlink'):
                evidence['rows'].extend(compare(source + '-repaired-failure', source, cwd, flags,
                    packets['backend-error'], kind, prior, 'RGECF1', 0))
            evidence['rows'].extend(compare(source + '-unchanged-hit', source, cwd, flags, pristine,
                                            'regular', prior, 'RGECH1', 0))
            size = struct.unpack_from('<Q', pristine, 6)[0]
            state = input_state(pristine[14:14 + size])
            headers = [(os.path.abspath(os.path.join(cwd, name)), content) for name, content in state['files']
                       if name.endswith('.h')]
            headers = [(path, content) for path, content in headers if path.startswith(cwd + '/') and os.path.isfile(path)]
            preferred = 'FuzzerDefs.h' if source.endswith('.cpp') else 'zlib.h'
            headers.sort(key=lambda pair: (os.path.basename(pair[0]) != preferred, pair[0]))
            assert headers, state['files']
            header_path, header = headers[0]
            assert open(header_path, 'rb').read() == header
            header_stat = os.stat(header_path)
            changed_header = header + b'\ntypedef int rgec_real_included_header_edit;\n'
            save(source, 'header.original', header); save(source, 'header.edited', changed_header)
            open(header_path, 'wb').write(changed_header)
            for kind in ('regular', 'hardlink'):
                rows = compare(source + '-included-header-edit', source, cwd, flags, pristine,
                               kind, prior, 'RGECF1', 0)
                evidence['rows'].extend(rows)
                evidence['header_checks'].append({'source': source, 'header_path': header_path,
                    'kind': kind, 'original_sha256': sha(header), 'edited_sha256': sha(changed_header),
                    'same_native_bitcode': state['bitcode_sha256'] == rows[1]['input_state']['bitcode_sha256'],
                    'exact_key_changed': rows[1]['key_sha256'] != sha(pristine[14:14 + size])})
            open(header_path, 'wb').write(header)
            os.utime(header_path, ns=(header_stat.st_atime_ns, header_stat.st_mtime_ns)); header_path = None
            assembly = original + b'\n__asm__(".incbin \\"/src/zlib/zlib.h\\"");\n'
            open(source_path, 'wb').write(assembly); save(source, 'file-assembly.source', assembly)
            evidence['rows'].extend(compare(source + '-file-assembly', source, cwd, flags, pristine,
                                            'regular', prior, 'RGECP1', 0))
            open(source_path, 'wb').write(original)
            for label, malformed in (('bad-magic', b'BROKEN' + pristine[6:]), ('truncated', pristine[:-1])):
                save(source + '-' + label, 'packet', malformed)
                evidence['rows'].extend(compare(source + '-' + label, source, cwd, flags, malformed,
                                                'regular', prior, 'RGECF1', 0))
            failed = original + b'\n#error RGEC genuine frontend failure\n'
            open(source_path, 'wb').write(failed); save(source, 'frontend-error.source', failed)
            evidence['rows'].extend(compare(source + '-frontend-error', source, cwd, flags, pristine,
                                            'regular', prior, '', 1))
        finally:
            open(source_path, 'wb').write(original)
            os.utime(source_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            if header_path:
                open(header_path, 'wb').write(header)
                os.utime(header_path, ns=(header_stat.st_atime_ns, header_stat.st_mtime_ns))
            with open(ROOT + '/evidence.json', 'w') as stream:
                json.dump(evidence, stream, indent=2)
    print(json.dumps({'pairs': len(evidence['rows']) // 2, 'header_checks': len(evidence['header_checks'])}), flush=True)


if __name__ == '__main__':
    main()
