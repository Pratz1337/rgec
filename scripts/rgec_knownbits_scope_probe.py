"""Complete real builds, native-answer witnesses and fresh-process reuse on Modal."""
import hashlib
import json
import os
import random
import resource
import shlex
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import traceback

sys.path.insert(0, '/')
from modal_recipient_entry import ENV, drop

def sha(data): return hashlib.sha256(data).hexdigest()

config = json.load(open('/knownbits-scope-config.json'))
target = '/retained/' + config['prefix']; os.mkdir(target)
folder = '/workspace/knownbits-evidence'; os.mkdir(folder)
project = '/workspace/backend-continuation/project'
os.makedirs(os.path.dirname(project), exist_ok=True)
for name, fd in (('stdout', 1), ('stderr', 2)):
    stream = open(target + '/' + name, 'wb'); os.dup2(stream.fileno(), fd)
result = dict(returncode=1)
evidence = dict(rows=[], plans=[], seed=11017, blocks=config['blocks'], native_closure_certified=False,
    adaptive_noninterference_proved=False, substantial_novelty_established=False,
    scope='Source-derived scalar structural scope, trusted same-binary native packets, genuine complete zlib builds and upstream tests, real repository round trips and held-out C++ compilation. Entry projection precedes lookup. Finite shadow checks are not native semantic certificates; allocator/fault/resource/physical-observer equivalence is not established.')

def save(name, data):
    path = folder + '/' + name
    with open(path, 'wb') as f: f.write(data)
    return sha(data)

def persist(): save('evidence.json', (json.dumps(evidence, indent=2) + '\n').encode())

def execute(argv, cwd, label, env, contents=None, allowed=(0,)):
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    own = resource.getrusage(resource.RUSAGE_SELF); start = time.monotonic()
    p = subprocess.Popen(argv, cwd=cwd, env=env, preexec_fn=drop, close_fds=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try: out, error = p.communicate(contents, timeout=900)
    except subprocess.TimeoutExpired:
        p.kill(); out, error = p.communicate(); save(label + '.stdout', out); save(label + '.stderr', error); raise
    after = resource.getrusage(resource.RUSAGE_CHILDREN); own_after = resource.getrusage(resource.RUSAGE_SELF)
    row = dict(label=label, argv=argv, cwd=cwd, returncode=p.returncode,
        wall_seconds=time.monotonic()-start,
        child_cpu_seconds=after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime,
        controller_cpu_seconds=own_after.ru_utime+own_after.ru_stime-own.ru_utime-own.ru_stime,
        stdout_sha256=save(label+'.stdout', out), stderr_sha256=save(label+'.stderr', error))
    if p.returncode not in allowed: raise RuntimeError((row, error[-3000:], out[-3000:]))
    return row, out, error

def metrics(path):
    totals = [0] * 12; names = []
    for name in sorted(os.listdir(path)):
        if not name.endswith('.metrics'): continue
        body = open(path + '/' + name, 'rb').read(); assert len(body) == 96
        values = struct.unpack('<12Q', body); assert values[6] == values[7] == 0
        assert values[1] + values[4] <= values[0] and values[2] + values[3] <= values[1]
        totals = [a+b for a,b in zip(totals, values)]; names.append(name)
    return dict(zip(('calls','admitted','hits','misses','rejected','shadow_checks','native_disagreements',
        'key_conflicts','stored','replacements','imported','direct_evaluations'), totals)), names

def fresh_project():
    if os.path.exists(project): shutil.rmtree(project)
    shutil.copytree('/src/zlib', project, ignore=shutil.ignore_patterns('.git', '*.o', '*.a', '*.so', '*.so.*',
        'example', 'minigzip', 'example64', 'minigzip64'))
    for directory, _, files in os.walk(project):
        os.chown(directory, 65534, 65534)
        for name in files: os.chown(directory + '/' + name, 65534, 65534)

def workflow(label, mode, peer=None):
    fresh_project()
    actions = folder + '/' + label; os.mkdir(actions); os.chown(actions, 65534, 65534)
    env = dict(ENV, CC='/usr/local/bin/clang', CFLAGS=' '.join(shlex.quote(f) for f in config['flags'] + ['-fPIC']))
    configure, _, _ = execute(['./configure', '--static'], project, label+'-configure', env)
    env.update(RGEC_KNOWNBITS_MODE=mode, RGEC_KNOWNBITS_ACTIONS=actions)
    if peer: env['RGEC_KNOWNBITS_PEER'] = peer
    build, _, _ = execute(['/usr/bin/make', '-j1', 'CC=/rgec-knownbits-driver'], project, label+'-build', env)
    tests, _, _ = execute(['/usr/bin/make', 'test'], project, label+'-test', dict(ENV))
    row = dict(label=label, mode=mode, peer=peer, configure=configure, build=build, tests=tests,
        roundtrips=[], artifacts={}, metrics=metrics(actions)[0])
    action_rows = [json.loads(line) for line in open(actions+'/actions.jsonl')]
    row['compiler_actions'] = action_rows
    assert len(action_rows) == 23 and sum(a['plan'] is not None for a in action_rows) == 19
    for path in ('/src/zlib/README', '/src/zlib/zlib.h', '/src/libfuzzer/FuzzerUtil.cpp'):
        body = open(path,'rb').read(); name = os.path.basename(path)
        encode, compressed, _ = execute(['./minigzip'], project, label+'-encode-'+name, dict(ENV), body)
        decode, restored, _ = execute(['./minigzip','-d'], project, label+'-decode-'+name, dict(ENV), compressed)
        assert body == restored
        row['roundtrips'].append(dict(path=path, input_sha256=sha(body), decoded_sha256=sha(restored),
            compressed_sha256=sha(compressed), compressed_bytes=len(compressed), encode=encode, decode=decode))
    for directory, _, files in os.walk(project):
        for name in files:
            path = directory+'/'+name; relative = os.path.relpath(path,project)
            if name.endswith(('.c','.h')) and name != 'zconf.h':
                assert open(path,'rb').read() == open('/src/zlib/'+relative,'rb').read()
            if name.endswith(('.o','.a')) or name in ('example','minigzip','example64','minigzip64'):
                body = open(path,'rb').read()
                row['artifacts'][relative] = dict(bytes=len(body), sha256=save(label+'-artifact-'+relative.replace('/','__'),body))
    assert len([p for p in row['artifacts'] if p.endswith('.o')]) == 19
    evidence['rows'].append(row); persist()
    print(label, row['metrics'], build['child_cpu_seconds'], flush=True)
    return row, actions

def equivalent(row, reference):
    checks = dict(artifacts=row['artifacts'] == reference['artifacts'],
        literal_compiler_status_streams=all(all(a[k] == b[k] for k in ('returncode','stdout_sha256','stderr_sha256'))
            for a,b in zip(row['compiler_actions'], reference['compiler_actions'])),
        upstream_test_streams=all(row['tests'][k] == reference['tests'][k] for k in ('returncode','stdout_sha256','stderr_sha256')),
        roundtrips=all(all(a[k] == b[k] for k in ('input_sha256','decoded_sha256','compressed_sha256','compressed_bytes'))
            for a,b in zip(row['roundtrips'], reference['roundtrips'])))
    row['reference_checks'] = checks; persist(); assert all(checks.values()), checks

try:
    evidence['native_bindings_sha256'] = save('native-bindings.json', open('/knownbits-scope-binding.json','rb').read())
    evidence['tool_sha256'] = {p: sha(open(p,'rb').read()) for p in
        ('/usr/local/bin/clang','/rgec-knownbits-scope','/clang_knownbits_scope.cpp','/rgec-knownbits-driver')}
    assert evidence['tool_sha256']['/usr/local/bin/clang'] == config['native_sha256']
    assert evidence['tool_sha256']['/clang_knownbits_scope.cpp'] == config['scope_source_sha256']
    for relative in ('llvm/CodeGen/ISDOpcodes.h','llvm/Support/KnownBits.h','llvm/CodeGen/ValueTypes.h'):
        save('installed-'+relative.replace('/','__'),open('/usr/local/include/'+relative,'rb').read())
    producer, peer = workflow('producer-shadow','shadow')
    assert producer['metrics']['shadow_checks'] == producer['metrics']['admitted'] > 0
    rng = random.Random(evidence['seed'])
    for block in range(config['blocks']):
        order = ['original','native','guard','cache-cold','cache-peer','direct']; rng.shuffle(order)
        rows = []
        for mode in order:
            row, _ = workflow('zlib-b%d-%s'%(block,mode), 'cache' if mode.startswith('cache') else mode,
                peer if mode == 'cache-peer' else None)
            row.update(block=block, variant=mode, order=order.index(mode)); rows.append(row); persist()
        reference = next(r for r in rows if r['variant'] == 'original')
        for row in rows: equivalent(row, reference)
        equivalent(producer, reference)
    # An unchanged real C++ translation unit outside zlib, fresh process per mode.
    source = '/src/libfuzzer/FuzzerUtil.cpp'; body = open(source,'rb').read()
    save('FuzzerUtil.cpp.original', body); output = folder+'/FuzzerUtil.o'
    options = config['flags'] + ['-stdlib=libc++','-std=c++11','-c','FuzzerUtil.cpp','-o',output]
    plan, _, error = execute(['/usr/local/bin/clang++']+options+['-###'], '/src/libfuzzer','fuzzer-plan',dict(ENV))
    commands = [shlex.split(line) for line in error.decode().splitlines() if '"-cc1"' in line]
    assert len(commands) == 1; evidence['plans'].append(plan); evidence['held_out'] = []
    fuzzer_peer = folder+'/fuzzer.packet'
    for variant in ('shadow','original','native','guard','cache-cold','cache-peer','direct'):
        label = 'fuzzer-'+variant; mode = 'cache' if variant.startswith('cache') else variant
        env = dict(ENV, RGEC_KNOWNBITS_MODE=mode, RGEC_KNOWNBITS_METRICS=folder+'/'+label+'.metrics')
        if variant == 'shadow': env['RGEC_KNOWNBITS_EXPORT'] = fuzzer_peer
        if variant == 'cache-peer': env['RGEC_KNOWNBITS_IMPORT'] = fuzzer_peer
        os.chown(folder, 65534,65534)
        binary = '/usr/local/bin/clang' if variant == 'original' else '/rgec-knownbits-scope'
        row, _, _ = execute([binary]+commands[0][1:], '/src/libfuzzer',label,env)
        row.update(variant=variant, object_sha256=save(label+'.o',open(output,'rb').read()))
        if os.path.isfile(folder+'/'+label+'.metrics'):
            values=struct.unpack('<12Q',open(folder+'/'+label+'.metrics','rb').read()); row['metrics']=list(values)
            assert values[6] == values[7] == 0
        evidence['held_out'].append(row); persist()
    reference = next(r for r in evidence['held_out'] if r['variant']=='original')
    assert all(all(row[k] == reference[k] for k in ('returncode','stdout_sha256','stderr_sha256','object_sha256')) for row in evidence['held_out'])
    assert open(source,'rb').read() == body
    evidence['suite_complete'] = True; result['returncode'] = 0
except BaseException:
    traceback.print_exc()
finally:
    persist(); sys.stdout.flush(); sys.stderr.flush()
    with tarfile.open(target+'/raw.tar.gz','w:gz') as archive:
        for directory, _, files in os.walk(folder):
            for name in sorted(files):
                path = directory+'/'+name
                if path == folder+'/FuzzerUtil.o': continue
                archive.add(path,arcname='raw/'+os.path.relpath(path,folder))
    for name in ('raw.tar.gz','stdout','stderr'): result[name+'_sha256']=sha(open(target+'/'+name,'rb').read())
    with open(target+'/result.json','w') as f: json.dump(result,f,indent=2)
sys.exit(result['returncode'])
