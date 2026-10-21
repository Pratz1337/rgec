"""Measure real native optimization callbacks and their reuse scope on Modal."""
import json
import os
import sys

sys.path.insert(0, '/')
import rgec_residual_probe as residual
from rgec_backend_probe import ROOT, packet_info, reset, run, queue_signature
from rgec_native_effect_probe import FLAGS, signature


def main():
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    result = {'cases': [], 'complete_closure_certified': False}
    profiles = [('plain', []), ('remarks', ['-Rpass=.*']),
        ('remarks-w', ['-Rpass=.*', '-w']),
        ('remarks-no-everything', ['-Rpass=.*', '-Wno-everything']),
        ('optimization-record', ['-fsave-optimization-record'])]
    status, _, error = run(['/usr/local/bin/clang'] + FLAGS +
        ['-fPIC', '-c', 'deflate.c', '-o', ROOT + '/prior.o'], '/src/zlib')
    assert status == 0, error
    prior = open(ROOT + '/prior.o', 'rb').read()
    try:
        for path in ('/src/zlib/adler32.c', '/src/zlib/deflate.c', '/src/libfuzzer/FuzzerUtil.cpp'):
            cwd, source = os.path.dirname(path), os.path.basename(path)
            original = open(path, 'rb').read(); original_stat = os.stat(path)
            try:
                os.utime(path, (1641013200, 1641013200))
                for variant, flags in profiles:
                    if variant == 'optimization-record':
                        flags = flags + ['-foptimization-record-file=' + ROOT + '/action-' + source + '/remarks.yaml']
                    case = {'name': source + '-' + variant, 'source': source, 'source_path': path,
                        'cwd': cwd, 'variant': variant, 'mtime': 1641013200,
                        'compiler': '/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang',
                        'flags': FLAGS + (['-stdlib=libc++', '-std=c++11'] if source.endswith('.cpp') else ['-fPIC']) + flags}
                    residual.save(case['name'] + '.source', original)
                    native = residual.request(case, 'native', prior)
                    def optimization_record(label):
                        if variant != 'optimization-record': return None
                        data = open(ROOT + '/action-' + source + '/remarks.yaml', 'rb').read()
                        return {'bytes': len(data), 'sha256': residual.save(case['name'] + '-' + label + '.yaml', data)}
                    native_yaml = optimization_record('native')
                    if native_yaml is not None: assert native_yaml['bytes'] > 0
                    record = residual.request(case, 'record', prior)
                    record_yaml = optimization_record('record')
                    private = record['receipt'] == 'RGECP1'
                    if private:
                        status, packet, error, info, producer_object = None, None, None, None, None
                    else:
                        bound = open(ROOT + '/' + case['name'] + '.key', 'rb').read()
                        reset(ROOT + '/action-' + source, 'hardlink', prior)
                        status, packet, error = run(['/rgec-backend', '--rgec-produce-parametric'], cwd, None, bound)
                        residual.save(case['name'] + '.producer.packet', packet)
                        residual.save(case['name'] + '.producer.stderr', error)
                        output = ROOT + '/action-' + source + '/action.o'
                        producer_object = residual.save(case['name'] + '.producer.object.o',
                            open(output, 'rb').read()) if os.path.isfile(output) else None
                        info = packet_info(packet)
                    replay = residual.request(case, 'replay', prior, packet)
                    replay_yaml = optimization_record('replay')
                    checks = {'native_record_match': all(native[k] == record[k]
                        for k in ('returncode', 'stdout_sha256', 'stderr_sha256', 'object_sha256')),
                        'status_and_streams_match': all(native[k] == replay[k]
                        for k in ('returncode', 'stdout_sha256', 'stderr_sha256')),
                        'structural_effects_match': signature(native) == signature(replay),
                        'queued_event_roles_match': queue_signature(native['events']) == queue_signature(replay['events']),
                        'optimization_record_match': native_yaml == replay_yaml}
                    row = dict(case, native=native, record=record, replay=replay, producer_status=status,
                        producer_info=info, native_private=private,
                        producer_packet_sha256=residual.sha(packet) if packet is not None else None,
                        producer_stderr_sha256=residual.sha(error) if error is not None else None,
                        producer_object_sha256=producer_object, native_yaml=native_yaml,
                        record_yaml=record_yaml, replay_yaml=replay_yaml,
                        **checks)
                    result['cases'].append(row)
                    print(case['name'], packet[:6].decode() if packet is not None else 'RGECP1',
                        checks, flush=True)
            finally:
                os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    finally:
        result['comparison_mismatches'] = [row['name'] for row in result['cases']
            if not all(row[k] for k in ('native_record_match', 'status_and_streams_match',
                'structural_effects_match', 'queued_event_roles_match', 'optimization_record_match'))]
        with open(ROOT + '/evidence.json', 'w') as stream: json.dump(result, stream, indent=2)


if __name__ == '__main__':
    main()
