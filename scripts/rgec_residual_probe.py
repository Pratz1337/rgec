"""Real native input edits, inaccessible producer inputs, and recipient replay."""
import json
import os
import struct
import subprocess
import sys

sys.path.insert(0, '/')
from modal_recipient_entry import ENV, drop
from rgec_backend_probe import ROOT, driver, key, packet_info, reset, run, watch, queue_signature
from rgec_native_effect_probe import FLAGS, observe, sha, signature
from rgec_native_event_probe import events


def save(label, data):
    with open(ROOT + '/' + label, 'wb') as stream:
        stream.write(data)
    return sha(data)


def state_input(bound):
    offset = [0]
    def number():
        value = struct.unpack_from('<Q', bound, offset[0])[0]
        offset[0] += 8
        return value
    def field():
        length = number()
        value = bound[offset[0]:offset[0] + length]
        offset[0] += length
        assert len(value) == length
        return value
    arguments = [field().decode() for _ in range(number())]
    bitcode = field()
    count, end = number(), number()
    files = []
    for _ in range(1, count):
        number()
        if number():
            number(); number()
            files.append((field().decode(), field()))
        else:
            number(); number(); number(); number()
    assert bound[offset[0]:offset[0] + 6] == b'RGECS3'
    return {'arguments': arguments, 'bitcode_sha256': sha(bitcode), 'files': files,
            'source_map_entries': count, 'next_source_offset': end}


def request(case, mode, prior, packet=None):
    folder = ROOT + '/action-' + case['source']
    output = reset(folder, 'hardlink', prior)
    argv = [case['compiler']] + case['flags'] + ['-c', case['source'], '-o', output]
    if mode != 'native':
        argv = driver(argv, case['cwd'])
    paths = [output, folder + '/alias.o', folder + '/target.o']
    before = {path: observe(path) for path in paths}
    held = os.open(output, os.O_RDONLY)
    fd = watch(folder)
    status, control, diagnostic = run(argv, case['cwd'], None if mode in ('native', 'wrapped-cold') else mode, packet)
    queued = events(fd)
    bound, receipt = key(control) if mode in ('replay', 'wrapped-cold') else (None, b'')
    label = case['name'] + '-' + mode
    row = {'case': label, 'returncode': status, 'paths': paths, 'before': before,
        'after': {path: observe(path) for path in paths},
        'directory_entries_after': sorted(os.listdir(folder)), 'events': queued,
        'stdout_sha256': save(label + '.stdout', control if mode in ('native', 'wrapped-cold') else b''),
        'stderr_sha256': save(label + '.stderr', diagnostic),
        'control_sha256': save(label + '.control', control),
        'held_fd_content_sha256': save(label + '.held.o', os.read(held, 10000000)),
        'receipt': receipt.decode(), 'key_sha256': sha(bound) if bound else None}
    os.close(held)
    row['object_sha256'] = save(label + '.object.o', open(output, 'rb').read()) if os.path.isfile(output) else None
    if mode == 'record' and control[:6] in (b'RGECB1', b'RGECB2', b'RGECB3'):
        info = packet_info(control)
        size = struct.unpack_from('<Q', control, 6)[0]
        bound = control[14:14 + size]
        save(case['name'] + '.key', bound)
        save(case['name'] + '.packet', control)
        row.update(info=info, key_sha256=sha(bound))
    elif mode == 'record':
        if case.get('allow_prebackend_failure') and not control and status != 0:
            row['prebackend_failure'] = True
        else:
            assert control == b'RGECP1', control[:100]
            row['receipt'] = 'RGECP1'
    return row


def variants():
    return {
        'pristine': b'',
        'mapped-backend-error': b'\n#line 701 "rgec_mapped_native_source.c"\n'
            b'void rgec_actual_backend_error(void) { __asm__("rgec_invalid_instruction"); }\n',
        'source-mtime': b'\nconst char rgec_live_metadata[] = __TIMESTAMP__;\n'
            b'const char *rgec_live_metadata_value(void) { return rgec_live_metadata; }\n',
        'negative-include': b'\n#if __has_include("rgec_optional_real_header.h")\n'
            b'#include "rgec_optional_real_header.h"\n#else\n#define RGEC_OPTIONAL_VALUE 23\n#endif\n'
            b'int rgec_optional_dependency(void) { return RGEC_OPTIONAL_VALUE; }\n',
        'ast-warning': b'\nint rgec_native_stack_warning(int x) { volatile char a[4096]; a[0] = x; return a[0]; }\n',
        'ast-warning-as-error': b'\nint rgec_native_stack_warning(int x) { volatile char a[4096]; a[0] = x; return a[0]; }\n'
    }


def main(phase):
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    result = {'phase': phase, 'cases': [], 'complete_closure_certified': False,
              'adaptive_noninterference_proved': False}
    for path in ('/usr/local/bin/clang', '/rgec-backend', '/rgec-backend.cpp', '/clang_residual_backend.h', '/clang_backend_read_state.h'):
        result.setdefault('tool_sha256', {})[path] = sha(open(path, 'rb').read())
    try:
        if phase == 'capture':
            status, _, error = run(['/usr/local/bin/clang'] + FLAGS + ['-fPIC', '-c', 'deflate.c', '-o', ROOT + '/prior.o'], '/src/zlib')
            assert status == 0, error
            prior = open(ROOT + '/prior.o', 'rb').read()
            for source_path in ('/src/zlib/adler32.c', '/src/zlib/deflate.c', '/src/libfuzzer/FuzzerUtil.cpp'):
                cwd, source = os.path.dirname(source_path), os.path.basename(source_path)
                original = open(source_path, 'rb').read(); original_stat = os.stat(source_path)
                try:
                    for variant, suffix in variants().items():
                        changed = original + suffix
                        open(source_path, 'wb').write(changed)
                        os.utime(source_path, (1641013200, 1641013200))
                        case = {'name': source + '-' + variant, 'source': source, 'source_path': source_path,
                            'cwd': cwd, 'variant': variant, 'mtime': 1641013200,
                            'compiler': '/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang',
                            'flags': FLAGS + (['-stdlib=libc++', '-std=c++11'] if source.endswith('.cpp') else ['-fPIC'])}
                        if variant.startswith('ast-'):
                            case['flags'] += ['-Wframe-larger-than=1']
                        if variant == 'ast-error-limit':
                            case['flags'] += ['-ferror-limit=2']
                        if variant == 'ast-warning-as-error':
                            case['flags'] += ['-Werror=frame-larger-than=']
                        save(case['name'] + '.source', changed)
                        case['native'] = request(case, 'native', prior)
                        case['record'] = request(case, 'record', prior)
                        case['native_record_match'] = all(case['native'][field] == case['record'][field]
                            for field in ('returncode', 'stderr_sha256', 'object_sha256'))
                        assert case['native_record_match'], case
                        if variant in ('source-mtime', 'negative-include'):
                            if variant == 'source-mtime':
                                os.utime(source_path, (1641099600, 1641099600))
                            else:
                                open(cwd + '/rgec_optional_real_header.h', 'wb').write(b'#define RGEC_OPTIONAL_VALUE 71\n')
                            changed_case = dict(case, name=case['name'] + '-changed-prefix')
                            case['changed_live_prefix'] = request(changed_case, 'record', prior)
                            case['live_prefix_changed_key'] = case['changed_live_prefix']['key_sha256'] != case['record']['key_sha256']
                            case['live_prefix_changed_object'] = case['changed_live_prefix']['object_sha256'] != case['record']['object_sha256']
                            if variant == 'negative-include':
                                os.unlink(cwd + '/rgec_optional_real_header.h')
                        result['cases'].append(case)
                        print(case['name'], 'native capture matched', flush=True)
                finally:
                    open(source_path, 'wb').write(original)
                    os.utime(source_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        else:
            capture = json.load(open('/transfer-capture/evidence.json'))
            prior = open('/transfer-capture/prior.o', 'rb').read()
            if phase == 'producer':
                protected = set()
                for case in capture['cases']:
                    bound = open('/transfer-capture/' + case['name'] + '.key', 'rb').read()
                    for name, data in state_input(bound)['files']:
                        path = os.path.abspath(os.path.join(case['cwd'], name))
                        if name.startswith('<') or not os.path.isfile(path):
                            continue
                        protected.add(os.path.realpath(path))
                for path in protected:
                    os.chmod(path, 0)
                result['protected_input_files'] = sorted(protected)
            produced = json.load(open('/transfer-producer/evidence.json')) if phase == 'replay' else None
            for index, case in enumerate(capture['cases']):
                row = {'name': case['name'], 'variant': case['variant']}
                if phase == 'producer':
                    bound = open('/transfer-capture/' + case['name'] + '.key', 'rb').read()
                    inputs = state_input(bound)
                    reset(ROOT + '/action-' + case['source'], 'hardlink', prior)
                    status, out, error = run(['/rgec-backend', '-cc1'] + inputs['arguments'], case['cwd'], 'record')
                    row['fresh_frontend'] = {'returncode': status, 'control_sha256': save(case['name'] + '.fresh.control', out),
                        'stderr_sha256': save(case['name'] + '.fresh.stderr', error), 'packet_emitted': out.startswith(b'RGECB1')}
                    reset(ROOT + '/action-' + case['source'], 'hardlink', prior)
                    status, packet, error = run(['/rgec-backend', '--rgec-produce-residual'], case['cwd'], None, bound)
                    row.update(returncode=status, packet_sha256=save(case['name'] + '.packet', packet),
                        stderr_sha256=save(case['name'] + '.stderr', error), query_sha256=save(case['name'] + '.key', bound))
                    if packet.startswith(b'RGECB1'):
                        row['info'] = packet_info(packet)
                        row['key_matches'] = row['info']['key_sha256'] == sha(bound)
                        row['operations_match'] = row['info']['operations'] == case['record']['info']['operations']
                    else:
                        row.update(key_matches=False, operations_match=False)
                    output = ROOT + '/action-' + case['source'] + '/action.o'
                    row['object_sha256'] = save(case['name'] + '.object.o', open(output, 'rb').read()) if status == 0 and os.path.isfile(output) else None
                    row['native_status_object_match'] = (status, row['object_sha256']) == (
                        case['native']['returncode'], case['native']['object_sha256'])
                else:
                    source_path = case['source_path']
                    original = open(source_path, 'rb').read(); original_stat = os.stat(source_path)
                    try:
                        open(source_path, 'wb').write(open('/transfer-capture/' + case['name'] + '.source', 'rb').read())
                        os.utime(source_path, (case['mtime'], case['mtime']))
                        native = request(case, 'native', prior)
                        packet = open('/transfer-producer/' + case['name'] + '.packet', 'rb').read()
                        replay = request(case, 'replay', prior, packet)
                        row.update(native=native, replay=replay,
                            status_and_streams_match=all(native[field] == replay[field]
                                for field in ('returncode', 'stdout_sha256', 'stderr_sha256')),
                            structural_effects_match=signature(native) == signature(replay),
                            queued_event_roles_match=queue_signature(native['events']) == queue_signature(replay['events']))
                        row['producer_operations_match'] = produced['cases'][index]['operations_match']
                    finally:
                        open(source_path, 'wb').write(original)
                        os.utime(source_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                result['cases'].append(row)
                print(json.dumps(row, sort_keys=True), flush=True)
    finally:
        with open(ROOT + '/evidence.json', 'w') as stream:
            json.dump(result, stream, indent=2)


if __name__ == '__main__':
    main(sys.argv[1])
