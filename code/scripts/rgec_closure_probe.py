"""Native closure-dependency audit in the authentic Modal image, Python 3.5."""

import glob
import json
import os
import subprocess
import time

from rgec_native_effect_probe import FLAGS, command, sha


ROOT = '/workspace/closure'


def save(name, data):
    with open(ROOT + '/' + name, 'wb') as stream:
        stream.write(data)


def main():
    os.chmod('/workspace', 0o755)
    os.mkdir(ROOT)
    os.chown(ROOT, 65534, 65534)
    inventory = {pattern: glob.glob(pattern) for pattern in
                 ('/usr/local/include/clang/*', '/usr/local/include/llvm/*',
                  '/usr/local/lib/libclang*', '/usr/local/bin/llvm*', '/opt/*', '/llvm*')}
    version = subprocess.check_output(['/usr/local/bin/clang', '--version']).decode()
    evidence = {'platform': 'Modal', 'clang_version': version, 'tool_inventory': inventory,
                'actions': [], 'shared_reuse_enabled': False, 'complete_closure_certified': False}
    cases = [('zlib-adler32', '/src/zlib', 'adler32.c', [], FLAGS + ['-fPIC']),
             ('graphicsmagick-png', '/src/graphicsmagick', 'coders/png.c',
              ['-DHAVE_CONFIG_H', '-I.', '-I.', '-I/work/include'], FLAGS + ['-Wall'])]
    edits = [
        ('pristine', b''),
        ('clock', b'\nconst char rgec_clock_dependency[] = __TIME__;\n'),
        ('clock-alias', b'\n#define RGEC_REQUEST_CLOCK __TIME__\nconst char rgec_clock_dependency[] = RGEC_REQUEST_CLOCK;\n'),
        ('clock-diagnostic-suppressed', b'\n#pragma clang diagnostic push\n#pragma clang diagnostic ignored "-Wdate-time"\nconst char rgec_clock_dependency[] = __TIME__;\n#pragma clang diagnostic pop\n'),
        ('source-mtime', b'\nconst char rgec_metadata_dependency[] = __TIMESTAMP__;\n'),
        ('undeclared-incbin', b'\n__asm__(".pushsection .rodata\\n.incbin \\\"/src/zlib/zlib.h\\\"\\n.popsection");\n'),
        ('clock-token-paste', b'\n#define RGEC_JOIN(A,B) A##B\nconst char rgec_clock_dependency[] = RGEC_JOIN(__TI,ME__);\n'),
        ('clock-redefined-constant', b'\n#undef __TIME__\n#define __TIME__ "constant"\nconst char rgec_clock_dependency[] = __TIME__;\n'),
        ('inactive-clock', b'\n#if 0\nconst char rgec_clock_dependency[] = __TIME__;\n#endif\n'),
        ('counter', b'\n#if __COUNTER__ == 0\nconst int rgec_counter_dependency = __COUNTER__;\n#endif\n'),
        ('include-level', b'\nconst int rgec_level_dependency = __INCLUDE_LEVEL__;\n'),
    ]
    for label, cwd, source, pp_flags, flags in cases:
        source_path = cwd + '/' + source
        with open(source_path, 'rb') as stream:
            original = stream.read()
        original_stat = os.stat(source_path)
        try:
            for kind, suffix in edits:
                value = original + suffix
                with open(source_path, 'wb') as stream:
                    stream.write(value)
                name = label + '-' + kind
                common = ['/usr/local/bin/clang'] + pp_flags + flags
                guard_code, guard_out, guard_error = command(common +
                    ['-E', '-Werror=date-time', source], cwd)
                save(name + '.guard.stdout', guard_out)
                save(name + '.guard.stderr', guard_error)
                rewrite_code, rewritten, rewrite_error = command(common +
                    ['-E', '-frewrite-includes', source], cwd)
                save(name + '.rewritten.c', rewritten)
                save(name + '.rewrite.stderr', rewrite_error)
                row = {'case': name, 'kind': kind, 'source_sha256': sha(value),
                       'guard_returncode': guard_code, 'rewrite_returncode': rewrite_code,
                       'rewrite_sha256': sha(rewritten), 'runs': []}
                plugin_code, plugin_out, plugin_error = command(common +
                    ['-Xclang', '-load', '-Xclang', '/rgec-closure.so', '-Xclang', '-add-plugin',
                     '-Xclang', 'rgec-closure', '-fsyntax-only', source], cwd)
                save(name + '.plugin.stdout', plugin_out)
                save(name + '.plugin.stderr', plugin_error)
                row['plugin_returncode'] = plugin_code
                try:
                    row['plugin_observations'] = json.loads(plugin_out.decode())
                except ValueError:
                    row['plugin_invalid_output'] = True
                    evidence['actions'].append(row)
                    with open(ROOT + '/evidence.json', 'w') as stream:
                        json.dump(evidence, stream, indent=2)
                    raise RuntimeError('native plugin did not issue its observation: ' + plugin_error.decode())
                observation = row['plugin_observations']
                row['known_dependency_check_passed'] = plugin_code == 0 and not (
                    observation['macro_dependencies'] or observation['inline_assembly'] or observation['syntax_errors'])
                for repetition in range(2):
                    if repetition:
                        time.sleep(2)  # Genuine independent wall clock; never inject a fake clock.
                        if kind == 'source-mtime':
                            os.utime(source_path, None)
                    output = ROOT + '/' + name + '-' + str(repetition) + '.o'
                    code, out, error = command(common + ['-c', source, '-o', output], cwd)
                    save(name + '-' + str(repetition) + '.stdout', out)
                    save(name + '-' + str(repetition) + '.stderr', error)
                    run = {'returncode': code, 'source_mtime_ns': os.stat(source_path).st_mtime_ns,
                           'stdout_sha256': sha(out), 'stderr_sha256': sha(error)}
                    if code == 0:
                        with open(output, 'rb') as stream:
                            run['object_sha256'] = sha(stream.read())
                    row['runs'].append(run)
                row['native_objects_equal'] = row['runs'][0].get('object_sha256') == row['runs'][1].get('object_sha256')
                row['both_native_compiles_succeeded'] = all(r['returncode'] == 0 for r in row['runs'])
                assert row['both_native_compiles_succeeded'], name
                evidence['actions'].append(row)
                with open(ROOT + '/evidence.json', 'w') as stream:
                    json.dump(evidence, stream, indent=2)
                print(name, 'guard', guard_code, 'known-check', row['known_dependency_check_passed'],
                      'native-equal', row['native_objects_equal'], flush=True)
        finally:
            with open(source_path, 'wb') as stream:
                stream.write(original)
            os.utime(source_path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    evidence['source_contents_and_mtimes_restored'] = True
    with open(ROOT + '/evidence.json', 'w') as stream:
        json.dump(evidence, stream, indent=2)


if __name__ == '__main__':
    main()
