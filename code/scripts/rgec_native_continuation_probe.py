"""Real native output-state comparisons inside the pinned Modal image."""
import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, '/rgec-trusted')
sys.path.insert(0, '/')
from modal_recipient_entry import ENV, drop
from rgec_native_effect_probe import FLAGS, observe, setup, sha, signature
from rgec_native_event_probe import events
import ctypes

ROOT = '/workspace/native-continuation'

def run(argv, cwd, payload=None):
    process = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=drop,
        close_fds=True, env=ENV)
    out, error = process.communicate(payload, timeout=120)
    return process.returncode, out, error

def watch(folder):
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    assert fd >= 0, ctypes.get_errno()
    assert libc.inotify_add_watch(fd, folder.encode(), 0x2 | 0x4 | 0x8 | 0x20 |
                                 0x40 | 0x80 | 0x100 | 0x200) >= 0, ctypes.get_errno()
    return fd

def queue_signature(rows):
    # Preserve the raw queue separately. This comparison ignores fresh random
    # temporary names and move cookies, so it is not distributional equality.
    return [{'mask': x['mask'], 'role': 'temporary' if x['name'].endswith('.tmp')
             else x['name']} for x in rows]

def main():
    os.mkdir(ROOT)
    os.chown(ROOT, 65534, 65534)
    kinds = ('absent', 'regular', 'hardlink', 'symlink', 'dangling-symlink',
             'readonly-output', 'directory', 'missing-parent', 'readonly-parent')
    evidence = {'shared_reuse_enabled': False, 'admission_certified': False,
                'full_trace_equivalence_certified': False, 'rows': []}
    payloads = {}
    for source in ('adler32.c', 'deflate.c'):
        path = ROOT + '/' + source + '.payload.o'
        code, out, error = run(['/usr/local/bin/clang'] + FLAGS +
            ['-fPIC', '-c', source, '-o', path], '/src/zlib')
        assert code == 0, error
        payloads[source] = open(path, 'rb').read()
    assert payloads['adler32.c'] != payloads['deflate.c']
    for source in ('adler32.c', 'deflate.c'):
        source_path = '/src/zlib/' + source
        original = open(source_path, 'rb').read()
        initial_stat = os.stat(source_path)
        prefix = ['/usr/local/bin/clang'] + FLAGS + ['-fPIC', '-c', source]
        payload = payloads[source]
        prior = payloads['deflate.c' if source == 'adler32.c' else 'adler32.c']
        try:
            for failed in (False, True):
                open(source_path, 'wb').write(original + b'\n#error RGEC actual native continuation failure\n'
                                            if failed else original)
                for kind in kinds:
                    pair = []
                    for mode in ('native', 'native-continuation'):
                        name = source + '-' + str(int(failed)) + '-' + kind + '-' + mode
                        folder = ROOT + '/' + source + '-' + str(int(failed)) + '-' + kind
                        assert os.path.dirname(os.path.realpath(folder)) == ROOT
                        if os.path.exists(folder):
                            shutil.rmtree(folder)
                        output = setup(folder, kind, prior)
                        paths = [output, folder + '/alias.o', folder + '/target.o']
                        before = {path: observe(path) for path in paths}
                        held = os.open(output, os.O_RDONLY) if kind in ('regular', 'hardlink', 'readonly-parent') else None
                        fd = watch(folder)
                        argv = prefix + ['-o', output]
                        if mode == 'native-continuation':
                            argv += ['-Xclang', '-load', '-Xclang', '/rgec-output-continuation.so',
                                     '-Xclang', '-plugin', '-Xclang', 'rgec-output-continuation']
                        code, out, error = run(argv, '/src/zlib', payload if mode != 'native' else None)
                        queue = events(fd)
                        row = {'case': name, 'source': source, 'failed_source': failed,
                            'kind': kind, 'mode': mode, 'argv': argv, 'returncode': code,
                            'stdout_sha256': sha(out), 'stderr_sha256': sha(error),
                            'paths': paths, 'before': before,
                            'after': {path: observe(path) for path in paths},
                            'directory_entries_after': sorted(os.listdir(folder)), 'events': queue}
                        if held is not None:
                            row['held_fd_content_sha256'] = sha(os.read(held, 1000000))
                            os.close(held)
                        for suffix, data in (('stdout', out), ('stderr', error)):
                            open(ROOT + '/' + name + '.' + suffix, 'wb').write(data)
                        evidence['rows'].append(row)
                        pair.append(row)
                    first, second = pair
                    second['structural_effects_match'] = signature(first) == signature(second)
                    second['status_and_stdout_match'] = (first['returncode'], first['stdout_sha256']) == \
                                                       (second['returncode'], second['stdout_sha256'])
                    second['diagnostics_match'] = first['stderr_sha256'] == second['stderr_sha256']
                    second['queued_event_roles_match'] = queue_signature(first['events']) == queue_signature(second['events'])
        finally:
            open(source_path, 'wb').write(original)
            os.utime(source_path, ns=(initial_stat.st_atime_ns, initial_stat.st_mtime_ns))
    with open(ROOT + '/evidence.json', 'w') as stream:
        json.dump(evidence, stream, indent=2)
    compared = [x for x in evidence['rows'] if x['mode'] == 'native-continuation']
    print(json.dumps({'native_driver_calls': len(evidence['rows']),
        'genuine_object_compiles': len(evidence['rows']) // 2 + 2,
        'state_pairs': len(compared),
        'structural_matches': sum(x['structural_effects_match'] for x in compared),
        'status_stdout_matches': sum(x['status_and_stdout_match'] for x in compared),
        'diagnostic_matches': sum(x['diagnostics_match'] for x in compared),
        'queued_event_role_matches': sum(x['queued_event_roles_match'] for x in compared)}))

if __name__ == '__main__':
    main()
