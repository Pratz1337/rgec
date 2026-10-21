"""Native/Riker cold/warm output-authority comparisons on authentic sources."""
import json
import os
import shlex
import subprocess
import sys

sys.path.insert(0, '/')
from modal_recipient_entry import drop
from rgec_backend_probe import ROOT, reset, watch, queue_signature
from rgec_native_effect_probe import observe, sha, signature
from rgec_native_event_probe import events


def main():
    os.makedirs(ROOT); os.chown(ROOT, 65534, 65534)
    result = {'cases': [], 'primes': [], 'noninterference_certified': False,
        'riker_history_filesystem': '/dev/shm', 'riker_native_mode': 'build --no-inject',
        'scope': 'Riker transcript/cache directories are distinct for cold and primed histories. Raw tool streams are retained, including baseline warnings.'}
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': ROOT}
    rkr = '/opt/riker/debug/bin/rkr'
    def command(argv, cwd):
        process = subprocess.Popen(argv, cwd=cwd, env=env, preexec_fn=drop,
            close_fds=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, error = process.communicate(timeout=180)
        return process.returncode, out, error
    def save(name, data):
        open(ROOT + '/' + name, 'wb').write(data)
        return sha(data)
    def persist(): open(ROOT + '/evidence.json', 'w').write(json.dumps(result, indent=2))
    try:
        code, out, error = command(['/usr/bin/clang', '-O1', '-fPIC', '-c', 'deflate.c', '-o', ROOT + '/prior.o'], '/src/zlib')
        assert code == 0, error
        prior = open(ROOT + '/prior.o', 'rb').read()
        result['native_fixture'] = {'returncode': code, 'object_sha256': sha(prior)}
        for cwd, source in (('/src/zlib', 'adler32.c'), ('/src/zlib', 'deflate.c'), ('/src/libfuzzer', 'FuzzerUtil.cpp')):
            compiler = '/usr/bin/clang++' if source.endswith('.cpp') else '/usr/bin/clang'
            flags = ['-O1'] + (['-std=c++11'] if source.endswith('.cpp') else ['-fPIC'])
            for kind in ('hardlink', 'readonly-output', 'missing-parent'):
                name = source + '-' + kind; folder = ROOT + '/action-' + name
                output = reset(folder, 'regular', prior)
                if kind == 'missing-parent':
                    os.mkdir(folder + '/missing'); os.chown(folder + '/missing', 65534, 65534)
                    output = folder + '/missing/action.o'
                argv = [compiler] + flags + ['-c', source, '-o', output]
                directories = {}
                for state in ('cold', 'warm'):
                    directory = '/dev/shm/rgec-riker-' + name + '-' + state
                    os.mkdir(directory); os.chown(directory, 65534, 65534)
                    script = '#!/bin/sh\ncd ' + shlex.quote(cwd) + '\nexec ' + shlex.join(argv) + '\n'
                    path = directory + '/Rikerfile'; open(path, 'w').write(script)
                    os.chown(path, 65534, 65534); os.chmod(path, 0o755)
                    directories[state] = directory
                code, out, error = command([rkr, 'build', '--no-inject'], directories['warm'])
                result['primes'].append({'name': name, 'returncode': code,
                    'stdout_sha256': save(name + '-prime.stdout', out), 'stderr_sha256': save(name + '-prime.stderr', error)})
                persist()
                assert code == 0 and os.path.isfile(output), error
                rows = []
                for mode in ('native', 'riker-cold', 'riker-warm'):
                    output = reset(folder, kind, prior)
                    paths = [output, folder + '/alias.o', folder + '/target.o']
                    before = {path: observe(path) for path in paths}
                    held = os.open(output, os.O_RDONLY) if os.path.isfile(output) else None
                    fd = watch(folder)
                    code, out, error = command(argv, cwd) if mode == 'native' else command([rkr, 'build', '--no-inject'], directories['cold' if mode == 'riker-cold' else 'warm'])
                    queued = events(fd); label = name + '-' + mode
                    row = {'case': label, 'mode': mode, 'returncode': code, 'paths': paths, 'before': before,
                        'after': {path: observe(path) for path in paths}, 'directory_entries_after': sorted(os.listdir(folder)),
                        'events': queued, 'stdout_sha256': save(label + '.stdout', out), 'stderr_sha256': save(label + '.stderr', error),
                        'held_fd_content_sha256': save(label + '.held.o', os.read(held, 10000000)) if held is not None else None,
                        'object_sha256': save(label + '.object.o', open(output, 'rb').read()) if os.path.isfile(output) else None}
                    if held is not None: os.close(held)
                    rows.append(row)
                native, cold, warm = rows
                result['cases'].append({'name': name, 'kind': kind, 'native': native, 'cold': cold, 'replay': warm,
                    'cold_warm_status_match': cold['returncode'] == warm['returncode'],
                    'native_warm_status_match': native['returncode'] == warm['returncode'],
                    'native_warm_streams_match': all(native[k] == warm[k] for k in ('stdout_sha256', 'stderr_sha256')),
                    'native_warm_structure_match': signature(native) == signature(warm),
                    'native_warm_root_event_roles_match': queue_signature(native['events']) == queue_signature(warm['events'])})
                persist(); print(name, [r['returncode'] for r in rows], flush=True)
    except Exception as error:
        result['error'] = str(error); raise
    finally: persist()


if __name__ == '__main__': main()
