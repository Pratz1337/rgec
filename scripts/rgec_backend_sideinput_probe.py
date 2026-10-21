"""Real symbol-map changes after the native backend cutpoint, Modal only."""
import json
import os
import sys

sys.path.insert(0, '/')
import rgec_residual_probe as residual
from rgec_backend_probe import ROOT, packet_info, reset, run, queue_signature
from rgec_native_effect_probe import FLAGS, sha, signature


def main():
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    result = {'cases': [], 'complete_closure_certified': False,
        'scope': 'Unchanged project functions; real native symbol-rewriter configuration files. No source functions or compiler diagnostics are fabricated.'}
    status, _, error = run(['/usr/local/bin/clang'] + FLAGS +
        ['-fPIC', '-c', 'deflate.c', '-o', ROOT + '/prior.o'], '/src/zlib')
    assert status == 0, error
    prior = open(ROOT + '/prior.o', 'rb').read()
    mapping = ROOT + '/rewrite-map.yaml'
    try:
        for path in ('/src/zlib/adler32.c', '/src/zlib/deflate.c', '/src/libfuzzer/FuzzerUtil.cpp'):
            original = open(path, 'rb').read()
            cwd, source = os.path.dirname(path), os.path.basename(path)
            case = {'name': source + '-unmapped', 'source': source, 'source_path': path,
                'cwd': cwd, 'source_sha256': residual.save(source + '.original', original),
                'compiler': '/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang',
                'flags': FLAGS + (['-stdlib=libc++', '-std=c++11'] if source.endswith('.cpp') else ['-fPIC'])}
            native_unmapped = residual.request(case, 'native', prior)
            assert native_unmapped['returncode'] == 0, native_unmapped
            object_path = ROOT + '/action-' + source + '/action.o'
            status, out, error = run(['/usr/bin/nm', '-g', '--defined-only', object_path], cwd)
            assert status == 0, error
            residual.save(source + '-unmapped.nm', out)
            functions = [line.split()[-1] for line in out.decode().splitlines() if len(line.split()) == 3 and line.split()[1] == 'T']
            symbol = ('adler32' if source == 'adler32.c' else 'deflate' if source == 'deflate.c'
                      else next(name for name in functions if 'SimpleFastHash' in name))
            assert symbol in functions
            case['symbol'] = symbol
            case['flags'] += ['-frewrite-map-file', mapping]
            observations = {}
            packet = None
            for version in ('A', 'B', 'missing'):
                if version == 'missing':
                    os.unlink(mapping)
                else:
                    contents = ('function: { source: "' + symbol + '", target: "rgec_actual_map_' + version + '" }\n').encode()
                    open(mapping, 'wb').write(contents); os.chmod(mapping, 0o644)
                    residual.save(source + '-map-' + version + '.yaml', contents)
                changed = dict(case, name=source + '-map-' + version)
                native = residual.request(changed, 'native', prior)
                observation = {'native': native, 'map_sha256': sha(open(mapping, 'rb').read()) if os.path.isfile(mapping) else None}
                if version != 'missing':
                    assert native['returncode'] == 0, native
                    status, symbols, error = run(['/usr/bin/nm', '-g', '--defined-only', object_path], cwd)
                    assert status == 0 and ('rgec_actual_map_' + version).encode() in symbols, (error, symbols)
                    residual.save(changed['name'] + '-native.nm', symbols)
                    record = residual.request(changed, 'record', prior)
                    observation['record'] = record
                    observation['native_record_match'] = all(native[k] == record[k] for k in
                        ('returncode', 'stdout_sha256', 'stderr_sha256', 'object_sha256'))
                    assert observation['native_record_match'], observation
                    if record['receipt'] != 'RGECP1':
                        bound = open(ROOT + '/' + changed['name'] + '.key', 'rb').read()
                        observation['bitcode_sha256'] = residual.state_input(bound)['bitcode_sha256']
                        if version == 'A':
                            reset(ROOT + '/action-' + source, 'hardlink', prior)
                            status, packet, error = run(['/rgec-backend', '--rgec-produce-parametric'], cwd, None, bound)
                            assert status == 0, error
                            observation['producer_status'] = status
                            observation['producer_info'] = packet_info(packet)
                            residual.save(source + '.producer.packet', packet)
                            residual.save(source + '.producer.stderr', error)
                            observation['producer_object_sha256'] = residual.save(source + '.producer.object.o', open(object_path, 'rb').read())
                            assert observation['producer_object_sha256'] == native['object_sha256']
                replay = residual.request(changed, 'replay', prior, packet)
                observation['replay'] = replay
                observation['native_replay_status_streams_match'] = all(native[k] == replay[k] for k in
                    ('returncode', 'stdout_sha256', 'stderr_sha256'))
                observation['native_replay_object_match'] = native['object_sha256'] == replay['object_sha256']
                observation['native_replay_structure_match'] = signature(native) == signature(replay)
                observation['native_replay_root_event_roles_match'] = queue_signature(native['events']) == queue_signature(replay['events'])
                observations[version] = observation
                print(source, version, native['returncode'], replay['returncode'], replay['receipt'], observation['native_replay_object_match'], flush=True)
            result['cases'].append(dict(case, observations=observations,
                source_unchanged=open(path, 'rb').read() == original,
                changed_map_changes_native_object=observations['A']['native']['object_sha256'] != observations['B']['native']['object_sha256'],
                captured_state_omits_map_change=bool(observations['A']['record'].get('key_sha256')) and observations['A']['record'].get('key_sha256') == observations['B']['record'].get('key_sha256'),
                captured_ir_same=bool(observations['A'].get('bitcode_sha256')) and observations['A'].get('bitcode_sha256') == observations['B'].get('bitcode_sha256'),
                stale_replay_observed=observations['B']['replay']['receipt'] == 'RGECH1' and not observations['B']['native_replay_object_match']))
            assert open(path, 'rb').read() == original
    finally:
        with open(ROOT + '/evidence.json', 'w') as stream: json.dump(result, stream, indent=2)


if __name__ == '__main__': main()
