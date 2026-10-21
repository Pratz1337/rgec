"""Run only inside the authentic Modal ARVO image (Python 3.5)."""

import ctypes
import hashlib
import json
import os
import stat
import subprocess
import sys
import time


ROOT = '/workspace/native-effects'
FLAGS = ['-O1', '-fno-omit-frame-pointer', '-gline-tables-only',
         '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION', '-fsanitize=address',
         '-fsanitize-address-use-after-scope', '-fsanitize=fuzzer-no-link']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def drop_authority():
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Word(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                   ('inheritable', ctypes.c_uint32)]
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.prctl(38, 1, 0, 0, 0) == 0
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    header, words = Header(0x20080522, 0), (Word * 2)()
    assert libc.capset(ctypes.byref(header), words) == 0
    assert libc.capget(ctypes.byref(header), words) == 0
    assert not any(getattr(w, f) for w in words for f in ('effective', 'permitted', 'inheritable'))


def command(argv, cwd, cache=None, log=None):
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
    if cache:
        env.update(CCACHE_DIR=cache, CCACHE_LOGFILE=log,
                   CCACHE_CONFIGPATH=ROOT + '/ccache.conf')
    process = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               preexec_fn=drop_authority, close_fds=True,
                               env=env)
    output, error = process.communicate(timeout=120)
    return process.returncode, output, error


def observe(path):
    try:
        value = os.lstat(path)
    except OSError as error:
        return {'errno': error.errno}
    row = {field: getattr(value, 'st_' + field) for field in
           ('mode', 'uid', 'gid', 'ino', 'nlink', 'size', 'mtime_ns', 'ctime_ns')}
    if stat.S_ISLNK(value.st_mode):
        row['symlink'] = os.readlink(path)
    try:
        with open(path, 'rb') as stream:
            row['content_sha256'] = sha(stream.read())
    except OSError as error:
        row['read_errno'] = error.errno
    return row


def setup(folder, kind, prior):
    os.mkdir(folder)
    os.chown(folder, 65534, 65534)
    output = folder + '/action.o'
    if kind in ('regular', 'hardlink', 'readonly-output', 'readonly-parent'):
        with open(output, 'wb') as stream:
            stream.write(prior)
        os.chown(output, 65534, 65534)
        os.chmod(output, 0o444 if kind == 'readonly-output' else 0o600)
    if kind == 'hardlink':
        os.link(output, folder + '/alias.o')
    if kind == 'symlink':
        with open(folder + '/target.o', 'wb') as stream:
            stream.write(prior)
        os.chown(folder + '/target.o', 65534, 65534)
        os.chmod(folder + '/target.o', 0o600)
        os.symlink('target.o', output)
    if kind == 'dangling-symlink':
        os.symlink('target.o', output)
    if kind == 'directory':
        os.mkdir(output)
    if kind == 'missing-parent':
        output = folder + '/missing/action.o'
    if kind == 'readonly-parent':
        os.chmod(folder, 0o555)
    return output


def signature(row):
    """A limited structural comparison, never full timestamp/inode equality."""
    result = {}
    for label, path in zip(('output', 'alias', 'target'), row['paths']):
        before, after = row['before'][path], row['after'][path]
        result[label] = {k: v for k, v in after.items()
                         if k not in ('ino', 'mtime_ns', 'ctime_ns')}
        result[label]['inode_changed'] = before.get('ino') != after.get('ino')
    result['held_fd_content_sha256'] = row.get('held_fd_content_sha256')
    result['directory_entries_after'] = row['directory_entries_after']
    return result


def residual(mode, directory, payload, stdout_file, stderr_file, failed):
    if mode == '--apply':
        from recipient_effect import EffectIneligible, RecipientOutput
        try:
            operation = RecipientOutput(directory, 'action.o')
        except EffectIneligible:
            return 77
        with open(payload, 'rb') as stream:
            value = stream.read()
        operation.finish(None if failed else value)
    elif not failed:
        with open(payload, 'rb') as stream:
            value = stream.read()
        with open(directory + '/action.o', 'wb') as stream:
            stream.write(value)
    for name, fd in ((stdout_file, 1), (stderr_file, 2)):
        with open(name, 'rb') as stream:
            os.write(fd, stream.read())
    return 1 if failed else 0


def repeat_permission_case(label, cwd, source, pp_flags, flags, prior):
    """Repeat the cache-state difference with exactly the same output argument."""
    folder = ROOT + '/repeat-' + label
    os.mkdir(folder)
    os.chown(folder, 65534, 65534)
    path = folder + '/action.o'
    compiler = ['/usr/local/bin/clang'] + pp_flags + flags + ['-c', source, '-o', path]
    ccache = '/opt/ccache/ccache'
    prime_code, _, error = command([ccache] + compiler[:-1] + [ROOT + '/' + label + '.prime.o'],
                                  cwd, ROOT + '/warm-cache', ROOT + '/' + label + '.repeat-prime.ccache-log')
    assert prime_code == 0, error
    results = []
    for repeat in range(2):
        for arm in ('cold', 'warm', 'recipient-guard'):
            with open(path, 'wb') as stream:
                stream.write(prior)
            os.chown(path, 65534, 65534)
            os.chmod(path, 0o444)
            before = observe(path)
            name = label + '-repeat-' + str(repeat) + '-' + arm
            if arm == 'recipient-guard':
                gate, _, gate_error = command(['/usr/bin/python3', __file__, '--apply', folder,
                    ROOT + '/' + label + '.payload.o', ROOT + '/' + label + '-absent-success.stdout',
                    ROOT + '/' + label + '-absent-success.stderr', '0'], cwd)
                assert gate == 77, gate_error
                code, out, error = command(compiler, cwd)
                cache_results = []
            else:
                cache = ROOT + '/warm-cache'
                if arm == 'cold':
                    cache = ROOT + '/' + name + '.cache'
                    os.mkdir(cache)
                    os.chown(cache, 65534, 65534)
                code, out, error = command([ccache] + compiler, cwd, cache, ROOT + '/' + name + '.ccache-log')
                with open(ROOT + '/' + name + '.ccache-log') as stream:
                    cache_results = [line.split('Result: ', 1)[1] for line in stream if 'Result: ' in line]
            for suffix, data in (('stdout', out), ('stderr', error)):
                with open(ROOT + '/' + name + '.' + suffix, 'wb') as stream:
                    stream.write(data)
            results.append({'case': name, 'repeat': repeat, 'arm': arm, 'compiler_argv': compiler,
                            'before': before, 'after': observe(path), 'returncode': code,
                            'stdout_sha256': sha(out), 'stderr_sha256': sha(error),
                            'ccache_results': cache_results,
                            'shared_lookup_attempted': arm != 'recipient-guard'})
    return results


def main():
    os.mkdir(ROOT)
    os.chown(ROOT, 65534, 65534)
    os.chmod('/workspace', 0o755)
    code, output, error = command(['/usr/local/bin/clang'] + FLAGS + ['-fPIC', '-c', 'deflate.c',
                                 '-o', ROOT + '/prior.o'], '/src/zlib')
    assert code == 0, error
    with open(ROOT + '/prior.o', 'rb') as stream:
        prior = stream.read()
    evidence = {'platform': 'Modal', 'prior_object_sha256': sha(prior), 'actions': [],
                'effect_comparisons': [], 'copy_counterexamples': [],
                'ccache_comparisons': [],
                'same_path_permission_repeats': [],
                'shared_reuse_enabled': False, 'complete_effect_certificate': False,
                'structural_signature_excludes': ['inode_numbers', 'mtime_ns', 'ctime_ns',
                                                   'partial_visibility', 'concurrent_tools']}
    ccache = '/opt/ccache/ccache'
    code, version, error = command([ccache, '--version'], '/src/zlib')
    assert code == 0, error
    evidence['ccache_version'] = version.decode()
    with open(ccache, 'rb') as stream:
        evidence['ccache_binary_sha256'] = sha(stream.read())
    with open(ROOT + '/ccache.conf', 'w') as stream:
        stream.write('max_size = 256M\n')
    os.mkdir(ROOT + '/warm-cache')
    os.chown(ROOT + '/warm-cache', 65534, 65534)
    cases = [('zlib-adler32', '/src/zlib', 'adler32.c', [], FLAGS + ['-fPIC']),
             ('graphicsmagick-png', '/src/graphicsmagick', 'coders/png.c',
              ['-DHAVE_CONFIG_H', '-I.', '-I.', '-I/work/include'], FLAGS + ['-Wall'])]
    kinds = ('absent', 'regular', 'hardlink', 'symlink', 'dangling-symlink',
             'readonly-output', 'readonly-parent', 'directory', 'missing-parent')
    for label, cwd, source, pp_flags, flags in cases:
        source_path = cwd + '/' + source
        with open(source_path, 'rb') as stream:
            original = stream.read()
        try:
            for failed in (False, True):
                actual = original + b'\n#error RGEC real-source failure control\n' if failed else original
                with open(source_path, 'wb') as stream:
                    stream.write(actual)
                if not failed:
                    prime_code, prime_out, prime_err = command([ccache, '/usr/local/bin/clang'] +
                        pp_flags + flags + ['-c', source, '-o', ROOT + '/' + label + '.prime.o'], cwd,
                        ROOT + '/warm-cache', ROOT + '/' + label + '.prime.ccache-log')
                    assert prime_code == 0, prime_err
                for kind in kinds:
                    name = label + '-' + kind + ('-failed' if failed else '-success')
                    folder = ROOT + '/' + name
                    path = setup(folder, kind, prior)
                    paths = [path, folder + '/alias.o', folder + '/target.o']
                    before = {p: observe(p) for p in paths}
                    held = None
                    if os.path.isfile(path):
                        held = open(path, 'rb')
                    start = time.monotonic()
                    code, stdout, stderr = command(['/usr/local/bin/clang'] + pp_flags + flags +
                                                   ['-c', source, '-o', path], cwd)
                    after = {p: observe(p) for p in paths}
                    row = {'case': name, 'kind': kind, 'source_mutated': failed, 'paths': paths,
                           'output_path': path,
                           'source_sha256': sha(actual), 'returncode': code,
                           'seconds': time.monotonic() - start, 'before': before, 'after': after,
                           'stdout_sha256': sha(stdout), 'stderr_sha256': sha(stderr),
                           'directory_entries_after': sorted(os.listdir(folder))}
                    if held:
                        row['held_fd_content_sha256'] = sha(held.read())
                        row['held_fd_inode_after'] = os.fstat(held.fileno()).st_ino
                        held.close()
                    for suffix, data in (('stdout', stdout), ('stderr', stderr)):
                        with open(ROOT + '/' + name + '.' + suffix, 'wb') as stream:
                            stream.write(data)
                    evidence['actions'].append(row)
                    if kind == 'absent' and not failed:
                        with open(path, 'rb') as stream:
                            artifact = stream.read()
                        with open(ROOT + '/' + label + '.payload.o', 'wb') as stream:
                            stream.write(artifact)
                    backend_name = label + '-absent' + ('-failed' if failed else '-success')
                    for mode in ('--apply', '--copy', '--ccache-cold', '--ccache-warm'):
                        if mode == '--copy' and kind not in ('regular', 'hardlink', 'symlink'):
                            continue
                        effect_folder = ROOT + '/' + name + mode
                        effect_path = setup(effect_folder, kind, prior)
                        effect_paths = [effect_path, effect_folder + '/alias.o', effect_folder + '/target.o']
                        effect_before = {p: observe(p) for p in effect_paths}
                        held = open(effect_path, 'rb') if os.path.isfile(effect_path) else None
                        # Missing parents are an actual before-lookup rejection;
                        # the real private native compiler handles that case.
                        if mode.startswith('--ccache'):
                            cache = ROOT + '/warm-cache'
                            if mode == '--ccache-cold':
                                cache = ROOT + '/' + name + '.cold-cache'
                                os.mkdir(cache)
                                os.chown(cache, 65534, 65534)
                            effect_code, effect_out, effect_err = command([ccache, '/usr/local/bin/clang'] +
                                pp_flags + flags + ['-c', source, '-o', effect_path], cwd, cache,
                                ROOT + '/' + name + mode + '.ccache-log')
                        elif kind == 'missing-parent':
                            effect_code, effect_out, effect_err = 77, b'', b''
                        else:
                            effect_code, effect_out, effect_err = command([
                                '/usr/bin/python3', __file__, mode, effect_folder,
                                ROOT + '/' + label + '.payload.o',
                                ROOT + '/' + backend_name + '.stdout',
                                ROOT + '/' + backend_name + '.stderr', str(int(failed))], cwd)
                        admitted = effect_code != 77
                        if not admitted:
                            effect_code, effect_out, effect_err = command(['/usr/local/bin/clang'] +
                                pp_flags + flags + ['-c', source, '-o', effect_path], cwd)
                        effect_row = {'paths': effect_paths, 'before': effect_before,
                                      'after': {p: observe(p) for p in effect_paths},
                                      'directory_entries_after': sorted(os.listdir(effect_folder))}
                        if held:
                            effect_row['held_fd_content_sha256'] = sha(held.read())
                            held.close()
                        comparison = {'case': name, 'mode': mode, 'admitted_before_lookup': admitted,
                                      'returncode': effect_code,
                                      'status_equals_native': effect_code == code,
                                      'structural_effects_equal': signature(row) == signature(effect_row),
                                      'stdout_equal': effect_out == stdout,
                                      # Fallback output-path diagnostics naturally contain
                                      # the different test directory. Preserve both raw.
                                      'stderr_equal': effect_err == stderr,
                                      'recipient_state': effect_row}
                        for suffix, data in (('stdout', effect_out), ('stderr', effect_err)):
                            with open(ROOT + '/' + name + mode + '.' + suffix, 'wb') as stream:
                                stream.write(data)
                        if mode.startswith('--ccache'):
                            with open(ROOT + '/' + name + mode + '.ccache-log') as stream:
                                cache_log = stream.read()
                            comparison['ccache_results'] = [line.split('Result: ', 1)[1]
                                for line in cache_log.splitlines() if 'Result: ' in line]
                            # This baseline has no RGEC admission boundary.
                            comparison.pop('admitted_before_lookup')
                            target = 'ccache_comparisons'
                        else:
                            target = 'effect_comparisons' if mode == '--apply' else 'copy_counterexamples'
                        evidence[target].append(comparison)
                    with open(ROOT + '/evidence.json', 'w') as stream:
                        json.dump(evidence, stream, indent=2)
                    print(name, code, flush=True)
        finally:
            with open(source_path, 'wb') as stream:
                stream.write(original)
        evidence['same_path_permission_repeats'].extend(
            repeat_permission_case(label, cwd, source, pp_flags, flags, prior))
    evidence['native_sources_restored'] = True
    with open(ROOT + '/evidence.json', 'w') as stream:
        json.dump(evidence, stream, indent=2)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        sys.exit(residual(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], bool(int(sys.argv[6]))))
    main()
