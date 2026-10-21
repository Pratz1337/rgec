"""Real compiler introspection reports and state-dependent finish, Modal only."""
import json
import os
import sys

sys.path.insert(0, '/')
import rgec_residual_probe as residual
from rgec_backend_probe import ROOT, run
from rgec_native_effect_probe import FLAGS, sha, signature


def main():
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    result = {'rows': [], 'tool_sha256': {}, 'complete_closure_certified': False,
              'adaptive_noninterference_proved': False,
              'scope': 'Unchanged authentic C/C++ bodies, actual native compiler flags and finish reports. Exact-context own packets; no synthetic functions or report replacement.'}
    for path in ('/usr/local/bin/clang', '/rgec-backend', '/rgec-backend.cpp',
                 '/clang_residual_backend.h', '/clang_backend_read_state.h'):
        result['tool_sha256'][path] = sha(open(path, 'rb').read())
    def persist(): residual.save('evidence.json', (json.dumps(result, indent=2) + '\n').encode())
    try:
        status, out, error = run(['/usr/local/bin/clang'] + FLAGS +
            ['-fPIC', '-c', 'deflate.c', '-o', ROOT + '/prior.o'], '/src/zlib')
        assert status == 0, error
        prior = open(ROOT + '/prior.o', 'rb').read()
        for path in ('/src/zlib/adler32.c', '/src/zlib/deflate.c', '/src/libfuzzer/FuzzerUtil.cpp'):
            original = open(path, 'rb').read()
            source, cwd = os.path.basename(path), os.path.dirname(path)
            residual.save(source + '.original', original)
            profiles = [('ordinary', []),
                ('ir-after-all', ['-mllvm', '-print-after-all', '-mllvm',
                    '-filter-print-funcs=' + ('adler32' if source == 'adler32.c' else
                        'deflate' if source == 'deflate.c' else '_ZN6fuzzer16NumberOfCpuCoresEv')]),
                ('pass-structure', ['-mllvm', '-debug-pass=Structure']),
                ('frontend-time', ['-ftime-report']),
                ('llvm-time', ['-mllvm', '-time-passes']),
                ('frontend-stats', ['-Xclang', '-print-stats']),
                ('frontend-stats-file', ['-Xclang', '-stats-file=' + ROOT + '/stats.json'])]
            for profile, extra in profiles:
                case = {'name': source + '-' + profile, 'source': source, 'source_path': path,
                    'allow_prebackend_failure': True,
                    'cwd': cwd, 'profile': profile, 'source_sha256': sha(original),
                    'compiler': '/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang',
                    'flags': FLAGS + (['-stdlib=libc++', '-std=c++11'] if source.endswith('.cpp') else ['-fPIC']) + extra}
                row = {'name': case['name'], 'profile': profile, 'source': source,
                       'flags': case['flags'], 'source_sha256': sha(original)}
                result['rows'].append(row)
                packet = None
                for mode in ('native', 'native-repeat', 'record', 'replay'):
                    if os.path.isfile(ROOT + '/stats.json'): os.unlink(ROOT + '/stats.json')
                    actual = 'native' if mode == 'native-repeat' else mode
                    request_case = dict(case, name=case['name'] + '-' + mode)
                    observation = residual.request(request_case, actual, prior, packet)
                    if os.path.isfile(ROOT + '/stats.json'):
                        contents = open(ROOT + '/stats.json', 'rb').read()
                        observation['stats_file_sha256'] = residual.save(case['name'] + '-' + mode + '.stats.json', contents)
                    else: observation['stats_file_sha256'] = None
                    row[mode] = observation
                    if mode == 'record' and observation.get('info'):
                        packet = open(ROOT + '/' + request_case['name'] + '.packet', 'rb').read()
                    if mode == 'record' and not packet:
                        if observation.get('receipt') == 'RGECP1' and os.path.isdir('/transfer-v23'):
                            filename = case['name'] + '-record.packet'
                            if not os.path.isfile('/transfer-v23/' + filename):
                                filename = source + '-ordinary-record.packet'
                            packet = open('/transfer-v23/' + filename, 'rb').read()
                            row['replay_packet_origin'] = 'frozen-v23/' + filename
                            row['replay_packet_sha256'] = sha(packet)
                        else:
                            row['replay_skipped_no_packet'] = True; break
                    persist()
                native = row['native']; repeat = row['native-repeat']
                row['native_repeat_streams_match'] = all(native[k] == repeat[k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256'))
                row['record_matches_native'] = all(native[k] == row['record'][k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256'))
                if 'replay' in row:
                    row['replay_matches_native'] = all(native[k] == row['replay'][k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256'))
                    row['replay_object_matches_native'] = native['object_sha256'] == row['replay']['object_sha256']
                    row['replay_structural_effects_match'] = signature(native) == signature(row['replay'])
                    row['replay_stats_match_native'] = native['stats_file_sha256'] == row['replay']['stats_file_sha256']
                print(case['name'], 'native', native['returncode'], 'record', row['record']['returncode'],
                    'route', row.get('replay', {}).get('receipt'), 'streams', row.get('replay_matches_native'), flush=True)
                assert open(path, 'rb').read() == original
                persist()
    finally: persist()


if __name__ == '__main__': main()
