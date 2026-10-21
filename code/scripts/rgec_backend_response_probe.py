"""Real native output-response counterexamples, using kernel devices and limits."""
import json
import os
import resource
import subprocess
import sys

sys.path.insert(0, '/')
from rgec_backend_probe import ROOT, driver, key, packet_info, reset, run, watch, queue_signature
from rgec_native_effect_probe import FLAGS, sha
from rgec_native_event_probe import events
from modal_recipient_entry import ENV, drop


def snapshot(path):
    try:
        item = os.lstat(path)
    except OSError as error:
        return {'errno': error.errno}
    row = {name: getattr(item, 'st_' + name) for name in ('mode', 'uid', 'gid', 'size', 'ino', 'nlink')}
    if os.path.islink(path):
        row['symlink'] = os.readlink(path)
    # Reading /dev/full or /dev/zero to EOF would be unbounded.
    if os.path.isfile(path):
        contents = open(path, 'rb').read(10000000)
        row['content_sha256'] = sha(contents)
    return row


def main():
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    evidence = {'rows': [], 'primes': [], 'crash_controls': [], 'response_independence_certified': False}
    code, out, error = run(['/usr/local/bin/clang'] + FLAGS + ['-fPIC', '-c', 'deflate.c', '-o', ROOT + '/prior.o'], '/src/zlib')
    assert code == 0, error
    prior = open(ROOT + '/prior.o', 'rb').read()
    try:
        for cwd, source in (('/src/zlib', 'adler32.c'), ('/src/zlib', 'deflate.c'), ('/src/libfuzzer', 'FuzzerUtil.cpp')):
            flags = FLAGS + (['-stdlib=libc++', '-std=c++11'] if source.endswith('.cpp') else ['-fPIC'])
            compiler = '/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang'
            folder = ROOT + '/action-' + source
            output = reset(folder, 'regular', prior)
            native = [compiler] + flags + ['-c', source, '-o', output]
            wrapped = driver(native, cwd)
            code, packet, error = run(wrapped, cwd, 'record')
            assert code == 0 and packet_info(packet)['reusable'], error
            open(ROOT + '/' + source + '.packet', 'wb').write(packet)
            evidence['primes'].append({'source': source, 'packet_sha256': sha(packet)})
            for fault in ('dev-full', 'file-size-limit'):
                pair = []
                modes = ('native', 'replay', 'native-repeat', 'record') if fault == 'file-size-limit' else ('native', 'replay')
                for mode in modes:
                    output = reset(folder, 'regular', prior)
                    if fault == 'dev-full':
                        assert os.path.exists('/dev/full')
                        os.unlink(output); os.symlink('/dev/full', output)
                    before = snapshot(output)
                    fd = watch(folder)
                    def authority():
                        drop()
                        if fault == 'file-size-limit':
                            resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))
                    env = dict(ENV)
                    instrumented = mode in ('replay', 'record')
                    if instrumented: env['RGEC_BACKEND_MODE'] = mode
                    process = subprocess.Popen(wrapped if instrumented else native,
                        executable='/usr/local/bin/clang' if instrumented else None,
                        cwd=cwd, env=env, preexec_fn=authority, stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
                    control, diagnostic = process.communicate(packet if mode == 'replay' else None, timeout=120)
                    bound, receipt = key(control) if mode == 'replay' else (None, control)
                    label = source + '-' + fault + '-' + mode
                    queued = events(fd)
                    row = {'case': label, 'source': source, 'fault': fault, 'mode': mode,
                        'returncode': process.returncode, 'before': before, 'after': snapshot(output),
                        'events': queued, 'directory_entries_after': sorted(os.listdir(folder)),
                        'receipt': receipt.decode(errors='replace') if mode == 'replay' else '',
                        'key_sha256': sha(bound) if bound else None, 'control_sha256': sha(control),
                        'stdout_sha256': sha(b'' if instrumented else control), 'stderr_sha256': sha(diagnostic)}
                    for ext, contents in (('control',control),('stderr',diagnostic),('stdout',b'' if instrumented else control)):
                        open(ROOT + '/' + label + '.' + ext, 'wb').write(contents)
                    if os.path.isfile(output):
                        open(ROOT + '/' + label + '.output.o', 'wb').write(open(output,'rb').read())
                    pair.append(row); evidence['rows'].append(row)
                first, second = pair[:2]
                second['status_and_streams_match'] = all(first[k]==second[k] for k in ('returncode','stdout_sha256','stderr_sha256'))
                second['event_roles_match'] = queue_signature(first['events'])==queue_signature(second['events'])
                print(source, fault, first['returncode'], second['returncode'], second['status_and_streams_match'], flush=True)
                if fault == 'file-size-limit':
                    repeat, cold = pair[2:]
                    evidence['crash_controls'].append({'source': source,
                        'native_repeat_status_match': first['returncode'] == repeat['returncode'],
                        'native_repeat_raw_stderr_match': first['stderr_sha256'] == repeat['stderr_sha256'],
                        'wrapped_cold_replay_status_match': cold['returncode'] == second['returncode'],
                        'wrapped_cold_replay_raw_stderr_match': cold['stderr_sha256'] == second['stderr_sha256'],
                        'wrapped_cold_native_raw_stderr_match': cold['stderr_sha256'] == first['stderr_sha256']})
    finally:
        with open(ROOT + '/evidence.json', 'w') as stream:
            json.dump(evidence, stream, indent=2)
    # Differences are research findings, not a reason to hide or abort collection.


if __name__ == '__main__':
    main()
