"""Count genuine native matcher work on unchanged real source, with native controls."""
import collections
import hashlib
import json
import os
import random
import shlex
import struct
import subprocess
import sys
import tarfile
import traceback

sys.path.insert(0, '/')
from modal_recipient_entry import ENV, drop


def sha(data): return hashlib.sha256(data).hexdigest()


config = json.load(open('/matcher-census-config.json'))
target = '/retained/' + config['prefix']; os.mkdir(target)
folder = '/workspace/matcher-census'; os.mkdir(folder); os.chown(folder, 65534, 65534)
for name, descriptor in (('stdout', 1), ('stderr', 2)):
    stream = open(target + '/' + name, 'wb'); os.dup2(stream.fileno(), descriptor)
evidence = dict(rows=[], plans=[], sources=[], seed=10117, complete_closure_certified=False,
    substantial_novelty_established=False,
    scope='Native invocation census and controls, with every native predicate retained. Classifiers describe branches and are not semantic admission or useful cache evidence.')
result = {'returncode': 1}


def save(name, data):
    with open(folder + '/' + name, 'wb') as f: f.write(data)
    return sha(data)


def persist(): save('evidence.json', (json.dumps(evidence, indent=2) + '\n').encode())


def execute(argv, cwd, label, census=False):
    env = dict(ENV); stream = None
    if census:
        stream = open(folder + '/' + label + '.census', 'wb')
        env['RGEC_MATCHER_CENSUS_FD'] = str(stream.fileno())
    p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        preexec_fn=drop, close_fds=True, pass_fds=(stream.fileno(),) if census else ())
    try: out, err = p.communicate(timeout=900)
    except subprocess.TimeoutExpired:
        p.kill(); out, err = p.communicate(); raise
    finally:
        if stream: stream.close()
    row = dict(label=label, argv=argv, cwd=cwd, returncode=p.returncode,
        stdout_sha256=save(label + '.stdout', out), stderr_sha256=save(label + '.stderr', err))
    return row, err


try:
    binding = open('/matcher-census-binding.json', 'rb').read()
    evidence['binding_sha256'] = save('matcher-census-binding.json', binding)
    evidence['tool_sha256'] = {path: sha(open(path, 'rb').read()) for path in
        ('/usr/local/bin/clang', '/rgec-matcher-census', '/rgec-backend.cpp', '/clang_matcher_census.cpp')}
    assert evidence['tool_sha256']['/usr/local/bin/clang'] == config['native_sha256']
    assert evidence['tool_sha256']['/rgec-backend.cpp'] == config['backend_source_sha256']
    assert evidence['tool_sha256']['/clang_matcher_census.cpp'] == config['census_source_sha256']
    assert json.loads(binding.decode())['patched_sha256'] == evidence['tool_sha256']['/rgec-matcher-census']
    flags = ['-O1', '-fno-omit-frame-pointer', '-gline-tables-only',
        '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION', '-fsanitize=address',
        '-fsanitize-address-use-after-scope', '-fsanitize=fuzzer-no-link']
    rng = random.Random(evidence['seed'])
    for path in ('/src/zlib/adler32.c', '/src/zlib/deflate.c', '/src/libfuzzer/FuzzerUtil.cpp'):
        body = open(path, 'rb').read(); name = os.path.basename(path); cwd = os.path.dirname(path)
        evidence['sources'].append(dict(path=path, sha256=save(name + '.original', body)))
        compiler = '/usr/local/bin/clang++' if name.endswith('.cpp') else '/usr/local/bin/clang'
        options = ['-stdlib=libc++', '-std=c++11'] if name.endswith('.cpp') else ['-fPIC']
        output = folder + '/action.o'
        plan, err = execute([compiler] + flags + options + ['-c', name, '-o', output, '-###'], cwd, name + '-plan')
        commands = [shlex.split(line) for line in err.decode().splitlines() if '"-cc1"' in line]
        assert plan['returncode'] == 0 and len(commands) == 1
        evidence['plans'].append(plan); persist()
        for block in range(2):
            order = ['native', 'census']; rng.shuffle(order)
            pair = []
            for mode in order:
                if os.path.exists(output): os.unlink(output)
                label = '%s-b%d-%s' % (name, block, mode)
                binary = '/usr/local/bin/clang' if mode == 'native' else '/rgec-matcher-census'
                row, err = execute([binary] + commands[0][1:], cwd, label, census=mode == 'census')
                row.update(source=name, block=block, mode=mode, order=order.index(mode))
                row['object_sha256'] = save(label + '.o', open(output, 'rb').read()) if os.path.isfile(output) else None
                if mode == 'census':
                    trace = open(folder + '/' + label + '.census', 'rb').read()
                    row['census_sha256'] = sha(trace); assert len(trace) % 80 == 0
                    counts = collections.Counter(); paths = collections.Counter(); checks = 0
                    for cursor in range(0, len(trace), 80):
                        words = struct.unpack_from('<10Q', trace, cursor)
                        assert words[0] == 0x524745434d435331 and words[1] in (0, 1, 2)
                        counts[str(words[1])] += 1
                        if words[1]:
                            paths['%d:%d' % (words[1], words[7])] += 1
                            if words[7] in (0, 1):
                                assert bool(words[8]) == (words[7] == 0); checks += 1
                    row.update(invocations=dict(counts), mask_paths=dict(paths), fast_classifications_checked=checks)
                    assert counts['0'] > 0, 'No real matcher-entry interception observed'
                evidence['rows'].append(row); pair.append(row); persist()
                assert row['returncode'] == 0, err
            assert all(pair[0][k] == pair[1][k] for k in ('returncode', 'object_sha256', 'stdout_sha256', 'stderr_sha256'))
        assert open(path, 'rb').read() == body
    evidence['suite_complete'] = True; result['returncode'] = 0
except BaseException:
    traceback.print_exc()
finally:
    persist(); sys.stdout.flush(); sys.stderr.flush()
    with tarfile.open(target + '/raw.tar.gz', 'w:gz') as archive:
        for name in sorted(os.listdir(folder)):
            if os.path.isfile(folder + '/' + name): archive.add(folder + '/' + name, arcname='raw/' + name)
    for name in ('raw.tar.gz', 'stdout', 'stderr'): result[name + '_sha256'] = sha(open(target + '/' + name, 'rb').read())
    with open(target + '/result.json', 'w') as output: json.dump(result, output, indent=2)
sys.exit(result['returncode'])
