"""Challenge the effect grammar with real native debug/coverage side files."""
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
                for variant, flags in (('debug', ['-g']), ('split-dwarf', ['-g', '-gsplit-dwarf']),
                                       ('coverage', ['--coverage'])):
                    case = {'name': source + '-' + variant, 'source': source, 'source_path': path,
                        'cwd': cwd, 'variant': variant, 'mtime': 1641013200,
                        'compiler': '/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang',
                        'flags': FLAGS + (['-stdlib=libc++', '-std=c++11'] if source.endswith('.cpp') else ['-fPIC']) + flags}
                    residual.save(case['name'] + '.source', original)
                    def sidefiles(label):
                        folder = ROOT + '/action-' + source
                        rows = {}
                        for name in sorted(os.listdir(folder)):
                            if name.endswith(('.dwo', '.gcno')):
                                data = open(folder + '/' + name, 'rb').read()
                                rows[name] = {'bytes': len(data), 'sha256': residual.save(
                                    case['name'] + '-' + label + '-' + name, data)}
                        return rows
                    native = residual.request(case, 'native', prior)
                    native_sidefiles = sidefiles('native')
                    assert native['returncode'] == 0, native
                    if variant != 'debug': assert native_sidefiles and all(r['bytes'] for r in native_sidefiles.values())
                    record = residual.request(case, 'record', prior)
                    record_sidefiles = sidefiles('record')
                    private = record['receipt'] == 'RGECP1'
                    status, packet, error, info, producer_object = None, None, None, None, None
                    if not private:
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
                    replay_sidefiles = sidefiles('replay')
                    checks = {'native_record_match': all(native[k] == record[k]
                        for k in ('returncode', 'stdout_sha256', 'stderr_sha256', 'object_sha256')) and native_sidefiles == record_sidefiles,
                        'status_and_streams_match': all(native[k] == replay[k]
                        for k in ('returncode', 'stdout_sha256', 'stderr_sha256')),
                        'structural_effects_match': signature(native) == signature(replay),
                        'queued_event_roles_match': queue_signature(native['events']) == queue_signature(replay['events']),
                        'sidefiles_match': native_sidefiles == replay_sidefiles}
                    result['cases'].append(dict(case, native=native, record=record, replay=replay,
                        producer_status=status, producer_info=info, native_private=private,
                        producer_packet_sha256=residual.sha(packet) if packet is not None else None,
                        producer_stderr_sha256=residual.sha(error) if error is not None else None,
                        producer_object_sha256=producer_object, native_sidefiles=native_sidefiles,
                        record_sidefiles=record_sidefiles, replay_sidefiles=replay_sidefiles, **checks))
                    print(case['name'], packet[:6].decode() if packet is not None else 'RGECP1', checks, flush=True)
            finally:
                os.utime(path, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    finally:
        result['comparison_mismatches'] = [r['name'] for r in result['cases'] if not all(r[k]
            for k in ('native_record_match', 'status_and_streams_match', 'structural_effects_match',
                      'queued_event_roles_match', 'sidefiles_match'))]
        with open(ROOT + '/evidence.json', 'w') as stream: json.dump(result, stream, indent=2)


if __name__ == '__main__':
    main()
