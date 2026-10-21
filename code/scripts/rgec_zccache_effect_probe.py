"""Pinned real staged-cache baseline versus native recipient output behavior."""
import glob
import json
import os
import subprocess
import sys

sys.path.insert(0, '/rgec-trusted')
sys.path.insert(0, '/')
from modal_recipient_entry import ENV, drop
from rgec_native_effect_probe import FLAGS, observe, sha

ROOT = '/workspace/zccache-effects'
ZC = '/opt/zccache/zccache'

def run(argv, env=None, payload=None):
    process = subprocess.Popen(argv, cwd='/src/zlib', stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env or ENV,
        preexec_fn=drop, close_fds=True)
    out, error = process.communicate(payload, timeout=120)
    return process.returncode, out, error

def journal(cache):
    rows = []
    for path in glob.glob(cache + '/**/compile_journal.jsonl', recursive=True):
        rows += [dict(json.loads(line), journal_path=path) for line in open(path) if line.strip()]
    return rows

def main():
    os.mkdir(ROOT)
    os.chown(ROOT, 65534, 65534)
    record = {'shared_policy_enabled': False, 'rows': [], 'prime': [], 'cache_modes': ['AUTO', 'COPY']}
    payloads = {}
    for source in ('adler32.c', 'deflate.c'):
        path = ROOT + '/' + source + '.payload.o'
        code, out, error = run(['/usr/local/bin/clang'] + FLAGS + ['-fPIC', '-c', source, '-o', path])
        assert code == 0, error
        payloads[source] = open(path, 'rb').read()
        for suffix, data in (('stdout', out), ('stderr', error)):
            open(path + '.' + suffix, 'wb').write(data)
    code, out, error = run([ZC, '--version'])
    record['version'] = out.decode()
    assert code == 0 and '1.15.1' in record['version'], error
    cache_roots = set()
    try:
        for source in ('adler32.c', 'deflate.c'):
            output = ROOT + '/' + source + '.action.o'
            compiler = ['/usr/local/bin/clang'] + FLAGS + ['-fPIC', '-c', source, '-o', output]
            payload = payloads[source]
            prior = payloads['deflate.c' if source == 'adler32.c' else 'adler32.c']
            for cache_mode in record['cache_modes']:
                warm = ROOT + '/' + source + '-' + cache_mode + '.warm'
                os.mkdir(warm)
                os.chown(warm, 65534, 65534)
                cache_roots.add(warm)
                env = dict(ENV, ZCCACHE_CACHE_DIR=warm, ZCCACHE_MODE=cache_mode,
                    ZCCACHE_PATH_REMAP='off', ZCCACHE_COMPILE_PRIORITY='normal')
                if os.path.exists(output):
                    os.chmod(output, 0o600)
                    os.unlink(output)
                code, out, error = run([ZC] + compiler, env)
                record['prime'].append({'source': source, 'cache_mode': cache_mode,
                    'returncode': code, 'stdout_sha256': sha(out), 'stderr_sha256': sha(error),
                    'journal': journal(warm), 'object': observe(output)})
                open(ROOT + '/' + source + '-' + cache_mode + '.prime.stdout', 'wb').write(out)
                open(ROOT + '/' + source + '-' + cache_mode + '.prime.stderr', 'wb').write(error)
                assert code == 0, error
                for repeat in range(2):
                    for mode in ('native', 'cold', 'warm', 'native-continuation'):
                        if os.path.exists(output):
                            os.chmod(output, 0o600)
                        open(output, 'wb').write(prior)
                        os.chown(output, 65534, 65534)
                        os.chmod(output, 0o444)
                        before = observe(output)
                        used_env, argv, stdin, cache = ENV, compiler, None, None
                        if mode in ('cold', 'warm'):
                            cache = warm
                            if mode == 'cold':
                                cache = ROOT + '/' + source + '-' + cache_mode + '-' + str(repeat) + '.cold'
                                os.mkdir(cache)
                                os.chown(cache, 65534, 65534)
                                cache_roots.add(cache)
                            used_env = dict(env, ZCCACHE_CACHE_DIR=cache)
                            argv = [ZC] + compiler
                        elif mode == 'native-continuation':
                            argv = compiler + ['-Xclang', '-load', '-Xclang', '/rgec-output-continuation.so',
                                '-Xclang', '-plugin', '-Xclang', 'rgec-output-continuation']
                            stdin = payload
                        previous = journal(cache) if cache else []
                        code, out, error = run(argv, used_env, stdin)
                        name = source + '-' + cache_mode + '-' + str(repeat) + '-' + mode
                        for suffix, data in (('stdout', out), ('stderr', error)):
                            open(ROOT + '/' + name + '.' + suffix, 'wb').write(data)
                        current = journal(cache) if cache else []
                        row = {'case': name, 'source': source, 'cache_mode': cache_mode,
                            'repeat': repeat, 'mode': mode, 'argv': argv, 'cache': cache,
                            'before': before, 'after': observe(output), 'returncode': code,
                            'stdout_sha256': sha(out), 'stderr_sha256': sha(error),
                            'new_journal_records': current[len(previous):]}
                        record['rows'].append(row)
                        print(name, code, [x.get('outcome') for x in row['new_journal_records']], flush=True)
    finally:
        for cache in cache_roots:
            code, out, error = run([ZC, 'stop'], dict(ENV, ZCCACHE_CACHE_DIR=cache))
            open(ROOT + '/' + os.path.basename(cache) + '.stop.stdout', 'wb').write(out)
            open(ROOT + '/' + os.path.basename(cache) + '.stop.stderr', 'wb').write(error)
        for cache in cache_roots:
            for path in glob.glob(cache + '/**/compile_journal.jsonl', recursive=True):
                record.setdefault('journals', {})[path] = [json.loads(line) for line in open(path) if line.strip()]
        open(ROOT + '/evidence.json', 'w').write(json.dumps(record, indent=2))

if __name__ == '__main__':
    main()
