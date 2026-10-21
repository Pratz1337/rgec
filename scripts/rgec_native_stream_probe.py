"""Actual unchanged project compilations, kernel failures and libc observations."""
import json
import os
import random
import resource
import shlex
import signal
import subprocess
import sys
import tarfile
import threading
import traceback

sys.path.insert(0, '/')
from modal_recipient_entry import ENV, drop
from rgec_backend_probe import ROOT, key, packet_info, reset, run, watch
from rgec_native_effect_probe import FLAGS, observe, sha
from rgec_native_event_probe import events


config = json.load(open('/stream-config.json'))
target = '/retained/' + config['prefix']
os.makedirs(target, mode=0o700)
stdout = open(target + '/stdout', 'wb'); stderr = open(target + '/stderr', 'wb')
os.dup2(stdout.fileno(), 1); os.dup2(stderr.fileno(), 2)
result = {'returncode': 1, 'tool_sha256': {}}
evidence = {'sources': [], 'rows': [], 'primes': [], 'plans': [], 'seed': 8117,
    'complete_closure_certified': False, 'adaptive_noninterference_proved': False,
    'scope': 'Unchanged zlib/libFuzzer bodies, real kernel output failures. A libc interposer observes returned calls; no forced results. Direct native cc1 and wrapped cc1. No timing claims or complete syscall coverage.'}


def save(name, contents):
    with open(ROOT + '/' + name, 'wb') as stream: stream.write(contents)
    return sha(contents)


def persist():
    save('evidence.json', (json.dumps(evidence, indent=2) + '\n').encode())


def request(case, label, mode, fault, traced, packet):
    output = reset(ROOT + '/action', 'regular', b'')
    if fault == 'dev-full':
        os.unlink(output); os.symlink('/dev/full', output)
    paths = [output]
    before = {path: observe(path) if fault != 'dev-full' else
              {'symlink': os.readlink(path), 'ino': os.lstat(path).st_ino} for path in paths}
    fd = watch(ROOT + '/action')
    env = dict(ENV)
    if mode in ('record', 'replay'): env['RGEC_BACKEND_MODE'] = mode
    read_fd = write_fd = None
    if traced:
        read_fd, write_fd = os.pipe()
        env.update(LD_PRELOAD='/rgec-stream-trace.so', RGEC_TRACE_FD=str(write_fd))
    def authority():
        drop()
        if fault.startswith('file-size-'):
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024, 1024))
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN if fault.endswith('error') else signal.SIG_DFL)
    argv = [('/usr/local/bin/clang' if mode == 'native' else '/rgec-backend')] + case['cc1']
    process = subprocess.Popen(argv, cwd=case['cwd'], env=env, preexec_fn=authority,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        close_fds=True, pass_fds=(() if write_fd is None else (write_fd,)))
    if traced:
        os.close(write_fd)
        def collect_trace():
            with os.fdopen(read_fd, 'rb') as stream, open(ROOT + '/' + label + '.trace', 'wb') as output_stream:
                while True:
                    chunk = stream.read(65536)
                    if not chunk: break
                    output_stream.write(chunk)
        collector = threading.Thread(target=collect_trace); collector.start()
    control, diagnostic = process.communicate(packet if mode == 'replay' else None, timeout=120)
    if traced: collector.join(timeout=30); assert not collector.is_alive()
    bound, receipt = key(control) if mode == 'replay' else (None, b'')
    # Never read a kernel device to EOF through its symlink.
    after = {output: observe(output) if not os.path.islink(output) else
             {'symlink': os.readlink(output), 'ino': os.lstat(output).st_ino}}
    row = {'label': label, 'source': case['source'], 'mode': mode, 'fault': fault,
        'traced': traced, 'argv': argv, 'returncode': process.returncode,
        'paths': paths, 'before': before, 'after': after,
        'directory_entries_after': sorted(os.listdir(ROOT + '/action')), 'events': events(fd),
        'control_sha256': save(label + '.control', control),
        'stdout_sha256': save(label + '.stdout', control if mode in ('native', 'wrapped') else b''),
        'stderr_sha256': save(label + '.stderr', diagnostic),
        'receipt': receipt.decode(errors='replace'), 'key_sha256': sha(bound) if bound is not None else None,
        'input_packet_sha256': sha(packet) if mode == 'replay' else None, 'object_sha256': None}
    if os.path.isfile(output) and not os.path.islink(output):
        row['object_sha256'] = save(label + '.object.o', open(output, 'rb').read())
    if traced: row['trace_sha256'] = sha(open(ROOT + '/' + label + '.trace', 'rb').read())
    if mode == 'record' and control[:6] in (b'RGECB1', b'RGECB2', b'RGECB3'):
        row['packet_info'] = packet_info(control)
    return row, control


try:
    for path, expected in config['tool_sha256'].items():
        result['tool_sha256'][path] = sha(open(path, 'rb').read())
        assert result['tool_sha256'][path] == expected, path
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    command = ['/usr/local/bin/clang', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
               '/rgec_native_stream_trace.c', '-ldl', '-o', '/rgec-stream-trace.so']
    build = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, error = build.communicate(timeout=120)
    evidence['tracer_build'] = {'argv': command, 'returncode': build.returncode,
        'stdout_sha256': save('tracer-build.stdout', out), 'stderr_sha256': save('tracer-build.stderr', error),
        'source_sha256': sha(open('/rgec_native_stream_trace.c', 'rb').read())}
    assert build.returncode == 0, error
    evidence['tracer_build']['binary_sha256'] = save('rgec-stream-trace.so', open('/rgec-stream-trace.so', 'rb').read())
    rng = random.Random(evidence['seed'])
    for path in ('/src/zlib/adler32.c', '/src/zlib/deflate.c', '/src/libfuzzer/FuzzerUtil.cpp'):
        original = open(path, 'rb').read(); source = os.path.basename(path); cwd = os.path.dirname(path)
        case = {'source': source, 'source_path': path, 'cwd': cwd,
                'source_sha256': save(source + '.original', original)}
        evidence['sources'].append(case)
        flags = FLAGS + (['-stdlib=libc++', '-std=c++11'] if source.endswith('.cpp') else ['-fPIC'])
        compiler = '/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang'
        argv = [compiler] + flags + ['-c', source, '-o', ROOT + '/action/action.o', '-###']
        code, out, error = run(argv, cwd)
        plan = [shlex.split(line) for line in error.decode().splitlines() if '"-cc1"' in line]
        assert code == 0 and len(plan) == 1 and plan[0][1] == '-cc1', error
        case['cc1'] = plan[0][1:]
        evidence['plans'].append({'source': source, 'argv': argv, 'returncode': code,
            'stdout_sha256': save(source + '.plan.stdout', out),
            'stderr_sha256': save(source + '.plan.stderr', error)})
        prime, packet = request(case, source + '-prime', 'record', 'regular', False, None)
        assert prime['returncode'] == 0 and prime['packet_info']['reusable'], prime
        evidence['primes'].append(prime); save(source + '.packet', packet); persist()
        for block in range(2):
            for fault in ('regular', 'dev-full', 'file-size-signal', 'file-size-error'):
                order = [(mode, traced) for mode in ('native', 'wrapped', 'record', 'replay') for traced in (False, True)]
                rng.shuffle(order)
                for mode, traced in order:
                    label = '%s-%s-b%d-%s-%s' % (source, fault, block, mode, 'traced' if traced else 'untraced')
                    row, _ = request(case, label, mode, fault, traced, packet)
                    row.update(block=block, order=order.index((mode, traced)))
                    evidence['rows'].append(row); persist()
                    print(label, row['returncode'], row['receipt'], flush=True)
                assert open(path, 'rb').read() == original
    evidence['suite_complete'] = True
    result['returncode'] = 0
except BaseException:
    traceback.print_exc()
finally:
    if os.path.isdir(ROOT): persist()
    sys.stdout.flush(); sys.stderr.flush()
    with tarfile.open(target + '/raw.tar.gz', 'w:gz') as archive:
        if os.path.isdir(ROOT):
            for name in sorted(os.listdir(ROOT)):
                path = ROOT + '/' + name
                if os.path.isfile(path): archive.add(path, arcname='raw/' + name)
    for name in ('raw.tar.gz', 'stdout', 'stderr'):
        result[name + '_sha256'] = sha(open(target + '/' + name, 'rb').read())
    with open(target + '/result.json', 'w') as stream: json.dump(result, stream, indent=2)
sys.exit(result['returncode'])
