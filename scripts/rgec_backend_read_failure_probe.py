"""Real repeated native/wrapped failure controls, including crash artifacts."""
import json
import os
import sys

sys.path.insert(0, '/')
import rgec_residual_probe as residual
from rgec_backend_probe import ROOT, packet_info, reset, run, queue_signature
from rgec_native_effect_probe import FLAGS, sha, signature


def main():
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    result = {'cases': [], 'bindings': [], 'complete_closure_certified': False,
              'scope': 'Repeated actual native failures before lookup; raw diagnostic bytes and genuine driver crash files preserved.'}
    status, _, error = run(['/usr/local/bin/clang'] + FLAGS +
        ['-fPIC', '-c', 'deflate.c', '-o', ROOT + '/prior.o'], '/src/zlib')
    assert status == 0, error
    prior = open(ROOT + '/prior.o', 'rb').read(); mapping = ROOT + '/rewrite-map.yaml'
    try:
        for path in ('/src/zlib/adler32.c', '/src/zlib/deflate.c', '/src/libfuzzer/FuzzerUtil.cpp'):
            original = open(path, 'rb').read()
            source, cwd = os.path.basename(path), os.path.dirname(path)
            case = {'name': source + '-unmapped', 'source': source, 'source_path': path, 'cwd': cwd,
                'source_sha256': residual.save(source + '.original', original),
                'compiler': '/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang',
                'flags': FLAGS + (['-stdlib=libc++', '-std=c++11'] if source.endswith('.cpp') else ['-fPIC'])}
            residual.request(case, 'native', prior)
            status, symbols, error = run(['/usr/bin/nm', '-g', '--defined-only',
                ROOT + '/action-' + source + '/action.o'], cwd)
            assert status == 0, error
            functions = [line.split()[-1] for line in symbols.decode().splitlines()
                if len(line.split()) == 3 and line.split()[1] == 'T']
            symbol = ('adler32' if source == 'adler32.c' else 'deflate' if source == 'deflate.c'
                else next(name for name in functions if 'SimpleFastHash' in name))
            data = ('function: { source: "' + symbol + '", target: "rgec_actual_map_A" }\n').encode()
            with open(mapping, 'wb') as stream: stream.write(data)
            os.chmod(mapping, 0o644)
            case['flags'] += ['-frewrite-map-file', mapping]; case['name'] = source + '-valid'
            native = residual.request(case, 'native', prior)
            record = residual.request(case, 'record', prior)
            bound = open(ROOT + '/' + case['name'] + '.key', 'rb').read()
            reset(ROOT + '/action-' + source, 'hardlink', prior)
            status, packet, error = run(['/rgec-backend', '--rgec-produce-parametric'], cwd, None, bound)
            info = packet_info(packet)
            assert status == 0 and info['reusable']
            result['bindings'].append({'source': source, 'source_sha256': case['source_sha256'],
                'native': native, 'record': record, 'producer_info': info, 'producer_returncode': status,
                'producer_packet_sha256': residual.save(source + '.producer.packet', packet),
                'producer_stderr_sha256': residual.save(source + '.producer.stderr', error)})
            for fault in ('unreadable', 'invalid'):
                with open(mapping, 'wb') as stream:
                    stream.write(data if fault == 'unreadable' else b'function: { source: "[", target: "x" }\n')
                os.chmod(mapping, 0 if fault == 'unreadable' else 0o644)
                traces = {}
                for role, mode in (('native-1', 'native'), ('native-2', 'native'),
                                   ('wrapped-cold', 'wrapped-cold'), ('replay', 'replay')):
                    before = set(os.listdir('/tmp'))
                    changed = dict(case, name=source + '-' + fault + '-' + role)
                    trace = residual.request(changed, mode, prior, packet if mode == 'replay' else None)
                    trace['crash_files'] = {}
                    for name in sorted(set(os.listdir('/tmp')) - before):
                        filename = '/tmp/' + name
                        if name.startswith(os.path.splitext(source)[0] + '-') and os.path.isfile(filename):
                            contents = open(filename, 'rb').read()
                            trace['crash_files'][filename] = {'bytes': len(contents),
                                'sha256': residual.save(changed['name'] + '-' + name, contents)}
                    traces[role] = trace
                row = {'source': source, 'fault': fault, 'traces': traces,
                    'native_repeat_stderr_equal': traces['native-1']['stderr_sha256'] == traces['native-2']['stderr_sha256'],
                    'wrapped_cold_replay_stderr_equal': traces['wrapped-cold']['stderr_sha256'] == traces['replay']['stderr_sha256'],
                    'all_native_statuses_equal': len({r['returncode'] for r in traces.values()}) == 1,
                    'no_wrapped_query': all(not traces[role]['key_sha256'] for role in ('wrapped-cold', 'replay')),
                    'measured_structures_equal': all(signature(trace) == signature(traces['native-1']) for trace in traces.values()),
                    'measured_root_event_roles_equal': all(queue_signature(trace['events']) == queue_signature(traces['native-1']['events']) for trace in traces.values())}
                result['cases'].append(row)
                print(source, fault, 'native-repeat-bytes', row['native_repeat_stderr_equal'],
                    'cold-replay-bytes', row['wrapped_cold_replay_stderr_equal'],
                    'no-query', row['no_wrapped_query'], flush=True)
            assert open(path, 'rb').read() == original
    finally:
        with open(ROOT + '/evidence.json', 'w') as stream: json.dump(result, stream, indent=2)


if __name__ == '__main__': main()
