"""Genuine native compiler and backend-continuation experiments, Modal only."""
import ctypes
import glob
import json
import os
import shlex
import shutil
import struct
import subprocess
import sys

sys.path.insert(0, '/rgec-trusted')
sys.path.insert(0, '/')
from modal_recipient_entry import ENV, drop
from rgec_native_effect_probe import FLAGS, observe, setup, sha, signature
from rgec_native_event_probe import events

ROOT = '/workspace/backend-continuation'


def run(argv, cwd, mode=None, packet=None):
    env = dict(ENV)
    if mode:
        env['RGEC_BACKEND_MODE'] = mode
    executable = '/usr/local/bin/clang' if argv[0] == '/rgec-driver/clang-7' else None
    process = subprocess.Popen(argv, executable=executable, cwd=cwd, env=env, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=drop, close_fds=True)
    out, error = process.communicate(packet, timeout=120)
    return process.returncode, out, error


def driver(argv, cwd):
    code, out, error = run(argv + ['-###'], cwd)
    assert code == 0, error
    for line in error.decode().splitlines():
        if '"-cc1"' in line:
            args = shlex.split(line)
            assert args[1] == '-cc1'
            resource = args[args.index('-resource-dir') + 1]
            wrapped = ['/rgec-driver/clang-7', '-no-canonical-prefixes',
                       '-ccc-install-dir', '/usr/local/bin', '-resource-dir', resource] + argv[1:]
            status, _, diagnostic = run(wrapped + ['-###'], cwd)
            assert status == 0, diagnostic
            commands = [shlex.split(item) for item in diagnostic.decode().splitlines() if '"-cc1"' in item]
            assert len(commands) == 1 and commands[0][0] == '/rgec-driver/clang-7', commands
            assert commands[0][1:] == args[1:], (commands[0], args)
            return wrapped
    raise AssertionError(error)


def key(control):
    if control.startswith(b'RGECQ1'):
        length = struct.unpack('<Q', control[6:14])[0]
        return control[14:14 + length], control[14 + length:]
    return None, control


def packet_info(packet):
    assert packet[:6] in (b'RGECB1', b'RGECB2', b'RGECB3'), packet[:100]
    offset = [6]
    def number():
        value = struct.unpack('<Q', packet[offset[0]:offset[0] + 8])[0]
        offset[0] += 8
        return value
    def field():
        size = number()
        value = packet[offset[0]:offset[0] + size]
        offset[0] += size
        return value
    bound = field()
    computation = field() if packet[:6] == b'RGECB2' else None
    if packet[:6] == b'RGECB3':
        computation, bound = bound, None
    reusable = number()
    frames = number()
    for _ in range(frames):
        number(); number(); field(); field()
    operations = []
    for _ in range(number()):
        kind, position, data = number(), number(), field()
        operations.append({'kind': kind, 'offset': position, 'bytes': len(data), 'sha256': sha(data)})
    assert offset[0] == len(packet)
    return {'key_sha256': sha(bound) if bound is not None else None,
            'key_bytes': len(bound) if bound is not None else None, 'reusable': bool(reusable),
            'computation_key_sha256': sha(computation) if computation is not None else None,
            'backend_created_source_buffers': frames, 'operations': operations}


def reset(folder, kind, prior):
    assert os.path.dirname(os.path.realpath(folder)) == ROOT
    if os.path.exists(folder):
        shutil.rmtree(folder)
    return setup(folder, kind, prior)


def watch(folder):
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    assert fd >= 0
    assert libc.inotify_add_watch(fd, folder.encode(), 0x2 | 0x4 | 0x8 | 0x20 |
                                 0x40 | 0x80 | 0x100 | 0x200) >= 0
    return fd


def queue_signature(queue):
    return [{'mask': row['mask'], 'role': 'temporary' if row['name'].endswith('.tmp')
             else row['name']} for row in queue]


def main():
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    sources = ['/src/zlib/adler32.c', '/src/zlib/deflate.c']
    cpp = glob.glob('/src/libfuzzer/FuzzerUtil.cpp')
    if not cpp:
        cpp = sorted(glob.glob('/src/libfuzzer/*.cpp'))
    assert cpp, 'authentic C++ source not found'
    sources.append(cpp[0])
    evidence = {'sources': sources, 'rows': [], 'primes': [], 'bindings': [],
                'complete_closure_certified': False, 'adaptive_noninterference_proved': False,
                'production_shared_policy_enabled': False}
    with open(ROOT + '/evidence.json', 'w') as stream:
        json.dump(evidence, stream, indent=2)
    fixture = ROOT + '/prior.o'
    code, out, error = run(['/usr/local/bin/clang'] + FLAGS +
        ['-fPIC', '-c', 'deflate.c', '-o', fixture], '/src/zlib')
    assert code == 0, error
    prior = open(fixture, 'rb').read()
    for source_path in sources:
        source, cwd = os.path.basename(source_path), os.path.dirname(source_path)
        original = open(source_path, 'rb').read()
        original_stat = os.stat(source_path)
        compiler = '/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang'
        flags = FLAGS + (['-stdlib=libc++', '-std=c++11'] if source.endswith('.cpp') else ['-fPIC'])
        folder = ROOT + '/action-' + source
        try:
            for variant in ('pristine', 'backend-error', 'frontend-warning'):
                suffix = {'pristine': b'',
                    'backend-error': b'\nvoid rgec_actual_backend_error(void) { __asm__("rgec_invalid_instruction"); }\n',
                    'frontend-warning': b'\n#warning RGEC genuine native frontend warning\n'}[variant]
                open(source_path, 'wb').write(original + suffix)
                output = reset(folder, 'regular', prior)
                argv = [compiler] + flags + ['-c', source, '-o', output]
                instrumented = driver(argv, cwd)
                code, packet, error = run(instrumented, cwd, 'record')
                info = packet_info(packet)
                assert info['reusable'], (source, variant, info)
                name = source + '-' + variant
                for extension, data in (('packet', packet), ('prime.stderr', error)):
                    open(ROOT + '/' + name + '.' + extension, 'wb').write(data)
                evidence['primes'].append({'case': name, 'returncode': code,
                    'packet_sha256': sha(packet), 'stderr_sha256': sha(error), 'info': info})
                assert code == (1 if variant == 'backend-error' else 0), error
                kinds = ('absent', 'regular', 'hardlink', 'symlink', 'dangling-symlink',
                         'readonly-output', 'directory', 'missing-parent', 'readonly-parent')
                if variant == 'frontend-warning':
                    kinds = ('regular', 'hardlink')
                for kind in kinds:
                    pair = []
                    for mode in ('native', 'replay'):
                        output = reset(folder, kind, prior)
                        # A missing-parent state changes argv and therefore the
                        # binding; obtain its real request arguments separately.
                        request = [compiler] + flags + ['-c', source, '-o', output]
                        native_args = driver(request, cwd) if mode == 'replay' else request
                        paths = [output, folder + '/alias.o', folder + '/target.o']
                        before = {path: observe(path) for path in paths}
                        held = os.open(output, os.O_RDONLY) if kind in ('regular', 'hardlink', 'readonly-parent') else None
                        fd = watch(folder)
                        status, control, diagnostics = run(native_args, cwd,
                            mode if mode == 'replay' else None, packet if mode == 'replay' else None)
                        queue = events(fd)
                        bound, receipt = key(control) if mode == 'replay' else (None, control)
                        row = {'case': name + '-' + kind + '-' + mode, 'source': source,
                            'variant': variant, 'kind': kind, 'mode': mode, 'returncode': status,
                            'stdout_sha256': sha(b'' if mode == 'replay' else control),
                            'stderr_sha256': sha(diagnostics), 'control_sha256': sha(control),
                            'key_sha256': sha(bound) if bound is not None else None,
                            'receipt': receipt.decode(errors='replace'), 'before': before,
                            'after': {path: observe(path) for path in paths}, 'paths': paths,
                            'directory_entries_after': sorted(os.listdir(folder)), 'events': queue}
                        if held is not None:
                            row['held_fd_content_sha256'] = sha(os.read(held, 1000000)); os.close(held)
                        for extension, data in (('stdout', b'' if mode == 'replay' else control),
                                                ('stderr', diagnostics), ('control', control)):
                            open(ROOT + '/' + row['case'] + '.' + extension, 'wb').write(data)
                        pair.append(row); evidence['rows'].append(row)
                    first, second = pair
                    second['structural_effects_match'] = signature(first) == signature(second)
                    second['status_and_streams_match'] = (first['returncode'], first['stdout_sha256'], first['stderr_sha256']) == \
                                                       (second['returncode'], second['stdout_sha256'], second['stderr_sha256'])
                    second['queued_event_roles_match'] = queue_signature(first['events']) == queue_signature(second['events'])
                    print(second['case'], second['receipt'], second['structural_effects_match'],
                          second['status_and_streams_match'], second['queued_event_roles_match'], flush=True)
                if variant == 'pristine':
                    changed = original + b'\nint rgec_real_bound_source_edit(void) { return 314159; }\n'
                    open(source_path, 'wb').write(changed)
                    outputs = []
                    for mode in ('native', 'replay'):
                        output = reset(folder, 'regular', prior)
                        status, control, diagnostics = run(argv if mode == 'native' else instrumented,
                            cwd, mode if mode == 'replay' else None, packet if mode == 'replay' else None)
                        bound, receipt = key(control) if mode == 'replay' else (None, control)
                        outputs.append({'mode': mode, 'returncode': status,
                            'object_sha256': sha(open(output, 'rb').read()), 'stderr_sha256': sha(diagnostics),
                            'key_sha256': sha(bound) if bound is not None else None, 'receipt': receipt.decode(errors='replace')})
                    assert outputs[0]['returncode'] == outputs[1]['returncode'] == 0
                    assert outputs[0]['object_sha256'] == outputs[1]['object_sha256']
                    assert outputs[1]['key_sha256'] != info['key_sha256'] and outputs[1]['receipt'] == 'RGECF1'
                    evidence['bindings'].append({'source': source, 'genuine_source_edit': True, 'rows': outputs})
            assert all(r['structural_effects_match'] and r['status_and_streams_match'] and
                       r['queued_event_roles_match'] for r in evidence['rows'] if r['mode'] == 'replay')
        finally:
            open(source_path, 'wb').write(original)
            os.utime(source_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
            with open(ROOT + '/evidence.json', 'w') as stream:
                json.dump(evidence, stream, indent=2)
    print(json.dumps({'pairs': len(evidence['rows']) // 2,
        'native_backend_recipes': len(evidence['primes']), 'genuine_binding_checks': len(evidence['bindings'])}), flush=True)


if __name__ == '__main__':
    main()
