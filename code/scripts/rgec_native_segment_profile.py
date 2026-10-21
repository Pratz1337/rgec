"""Profile authentic native compiler work on Modal; no cache is exercised."""
import hashlib
import json
import os
import random
import shlex
import subprocess
import sys
import tarfile
import time
import traceback

sys.path.insert(0, '/')
from modal_recipient_entry import ENV, drop


def sha(data):
    return hashlib.sha256(data).hexdigest()


config = json.load(open('/segment-profile-config.json'))
target = '/retained/' + config['prefix']
os.makedirs(target, mode=0o700)
folder = '/workspace/segment-profile'
os.mkdir(folder); os.chown(folder, 65534, 65534)
for name, descriptor in (('stdout', 1), ('stderr', 2)):
    stream = open(target + '/' + name, 'wb')
    os.dup2(stream.fileno(), descriptor)
result = {'returncode': 1}
evidence = {'rows': [], 'plans': [], 'sources': [], 'commands': [], 'seed': 10103,
    'scope': 'Native CPU sampling profiles for unchanged real translation units. Samples do not establish complete executed calls or read footprints. Profiles are not semantic certificates, timings are instrumentation costs, and no cache or noninterference claim is tested.',
    'complete_closure_certified': False, 'substantial_novelty_established': False}


def save(name, data):
    with open(folder + '/' + name, 'wb') as output: output.write(data)
    return sha(data)


def persist():
    save('evidence.json', (json.dumps(evidence, indent=2) + '\n').encode())


def execute(argv, cwd, label, recipient=True, timeout=900, environment=None):
    start = time.monotonic()
    process = subprocess.Popen(argv, cwd=cwd, env=ENV if environment is None else environment, close_fds=True,
        preexec_fn=drop if recipient else None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, error = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill(); out, error = process.communicate()
        save(label + '.stdout', out); save(label + '.stderr', error)
        raise
    row = {'argv': argv, 'cwd': cwd, 'label': label, 'returncode': process.returncode,
        'elapsed_seconds': time.monotonic() - start,
        'stdout_sha256': save(label + '.stdout', out),
        'stderr_sha256': save(label + '.stderr', error)}
    return row, out, error


try:
    native = '/usr/local/bin/clang'
    evidence['native_sha256'] = sha(open(native, 'rb').read())
    assert evidence['native_sha256'] == config['native_sha256']
    package_files = subprocess.check_output(['/usr/bin/dpkg-query', '-L', 'libgoogle-perftools4'])
    save('profiler-package-files.txt', package_files)
    profiler, = [path for path in package_files.decode().splitlines() if path.endswith('/libprofiler.so.0')]
    tools = [profiler, '/usr/bin/google-pprof', '/usr/bin/nm', '/usr/bin/objdump']
    evidence['tool_sha256'] = {path: sha(open(path, 'rb').read()) for path in tools}
    for label, argv in (
        ('package-versions', ['/usr/bin/dpkg-query', '-W', 'libgoogle-perftools4', 'google-perftools', 'libc6', 'binutils']),
        ('native-libraries', ['/usr/bin/ldd', native]),
        ('native-symbols', ['/usr/bin/nm', '-n', '-S', '--defined-only', native]),
        ('native-demangled-symbols', ['/usr/bin/nm', '-n', '-S', '-C', '--defined-only', native])):
        row, _, error = execute(argv, '/', label, recipient=False, timeout=120)
        evidence['commands'].append(row); persist()
        assert row['returncode'] == 0, error
    flags = ['-O1', '-fno-omit-frame-pointer', '-gline-tables-only',
        '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION', '-fsanitize=address',
        '-fsanitize-address-use-after-scope', '-fsanitize=fuzzer-no-link']
    rng = random.Random(evidence['seed'])
    for path in ('/src/zlib/adler32.c', '/src/zlib/deflate.c', '/src/libfuzzer/FuzzerUtil.cpp'):
        body = open(path, 'rb').read(); name = os.path.basename(path); cwd = os.path.dirname(path)
        evidence['sources'].append({'path': path, 'sha256': save(name + '.original', body)})
        output = folder + '/action.o'
        compiler = '/usr/local/bin/clang++' if name.endswith('.cpp') else native
        options = ['-stdlib=libc++', '-std=c++11'] if name.endswith('.cpp') else ['-fPIC']
        plan, _, error = execute([compiler] + flags + options + ['-c', name, '-o', output, '-###'],
            cwd, name + '-driver-plan')
        commands = [shlex.split(line) for line in error.decode().splitlines() if '"-cc1"' in line]
        assert plan['returncode'] == 0 and len(commands) == 1 and commands[0][1] == '-cc1', error
        evidence['plans'].append(plan); persist()
        cc1 = [native] + commands[0][1:]
        for block in range(3):
            order = ['native', 'sampled']; rng.shuffle(order)
            for mode in order:
                if os.path.exists(output): os.unlink(output)
                label = '%s-b%d-%s' % (name, block, mode)
                env = dict(ENV)
                if mode == 'sampled':
                    env.update(LD_PRELOAD=profiler, CPUPROFILE=folder + '/' + label + '.profile', CPUPROFILE_FREQUENCY='1000')
                row, _, error = execute(cc1, cwd, label, environment=env)
                row.update(source=name, mode=mode, block=block, order=order.index(mode))
                row['object_sha256'] = save(label + '.o', open(output, 'rb').read()) if os.path.isfile(output) else None
                recorded = folder + '/' + label + '.profile'
                if os.path.isfile(recorded): row['profile_sha256'] = sha(open(recorded, 'rb').read())
                evidence['rows'].append(row); persist()
                print(label, row['returncode'], row['elapsed_seconds'], flush=True)
                assert row['returncode'] == 0, error
                if mode == 'sampled':
                    annotation, _, problem = execute(['/usr/bin/google-pprof', '--text', '--nodefraction=0',
                        '--edgefraction=0', '--nodecount=100000', native, recorded], '/', label + '-annotation', recipient=False)
                    evidence['commands'].append(annotation); persist()
                    assert annotation['returncode'] == 0, problem
            pair = [row for row in evidence['rows'] if row['source'] == name and row['block'] == block]
            assert pair[0]['object_sha256'] == pair[1]['object_sha256']
            assert pair[0]['stdout_sha256'] == pair[1]['stdout_sha256']
        assert open(path, 'rb').read() == body
    evidence['suite_complete'] = True
    result['returncode'] = 0
except BaseException:
    traceback.print_exc()
finally:
    persist(); sys.stdout.flush(); sys.stderr.flush()
    with tarfile.open(target + '/raw.tar.gz', 'w:gz') as archive:
        for name in sorted(os.listdir(folder)):
            path = folder + '/' + name
            if os.path.isfile(path): archive.add(path, arcname='raw/' + name)
    for name in ('raw.tar.gz', 'stdout', 'stderr'):
        result[name + '_sha256'] = sha(open(target + '/' + name, 'rb').read())
    with open(target + '/result.json', 'w') as stream: json.dump(result, stream, indent=2)
sys.exit(result['returncode'])
