"""Real native reuse across source-local diagnostic policies, on Modal only."""
import json
import os
import struct
import sys

sys.path.insert(0, '/')
import rgec_residual_probe as residual
from rgec_backend_probe import ROOT, packet_info, reset, run, queue_signature
from rgec_native_effect_probe import signature, sha


def variants():
    body = b''.join(('int rgec_parametric_stack_' + str(i) +
        '(int x) { volatile char a[4096]; a[0] = x; return a[0]; }\n').encode() for i in range(5))
    def source(level):
        return (b'\n#pragma clang diagnostic push\n' +
            ('#pragma clang diagnostic ' + level.ljust(7) + ' "-Wframe-larger-than="\n').encode() +
            body + b'#pragma clang diagnostic pop\n')
    return {'ast-policy-warning': source('warning'), 'ast-policy-ignored': source('ignored'),
            'ast-policy-error': source('error'), 'ast-error-limit': source('error')}


def core(packet):
    assert packet[:6] == b'RGECB2'
    size = struct.unpack_from('<Q', packet, 6)[0]
    offset = 14 + size
    length = struct.unpack_from('<Q', packet, offset)[0]
    return packet[offset + 8:offset + 8 + length], offset + 8


def main(phase):
    if phase == 'capture':
        residual.variants = variants
        return residual.main(phase)
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    capture = json.load(open('/transfer-capture/evidence.json'))
    prior = open('/transfer-capture/prior.o', 'rb').read()
    result = {'phase': phase, 'cases': [], 'complete_closure_certified': False,
              'adaptive_noninterference_proved': False, 'parametric_effect_profile_certified': False}
    for path in ('/usr/local/bin/clang', '/rgec-backend', '/rgec-backend.cpp', '/clang_residual_backend.h'):
        result.setdefault('tool_sha256', {})[path] = sha(open(path, 'rb').read())
    try:
        if phase == 'producer':
            protected = set()
            for case in capture['cases']:
                bound = open('/transfer-capture/' + case['name'] + '.key', 'rb').read()
                for name, data in residual.state_input(bound)['files']:
                    path = os.path.abspath(os.path.join(case['cwd'], name))
                    if not name.startswith('<') and os.path.isfile(path):
                        protected.add(os.path.realpath(path))
            for path in protected: os.chmod(path, 0)
            result['protected_input_files'] = sorted(protected)
            for case in capture['cases']:
                name = case['name']
                bound = open('/transfer-capture/' + name + '.key', 'rb').read()
                inputs = residual.state_input(bound)
                reset(ROOT + '/action-' + case['source'], 'hardlink', prior)
                status, out, error = run(['/rgec-backend', '-cc1'] + inputs['arguments'], case['cwd'], 'record')
                fresh = {'returncode': status, 'packet_emitted': bool(out),
                    'control_sha256': residual.save(name + '.fresh.control', out),
                    'stderr_sha256': residual.save(name + '.fresh.stderr', error)}
                reset(ROOT + '/action-' + case['source'], 'hardlink', prior)
                status, packet, error = run(['/rgec-backend', '--rgec-produce-parametric'], case['cwd'], None, bound)
                info = packet_info(packet)
                output = ROOT + '/action-' + case['source'] + '/action.o'
                row = {'name': name, 'variant': case['variant'], 'returncode': status,
                    'fresh_frontend': fresh, 'info': info, 'key_matches': info['key_sha256'] == sha(bound),
                    'packet_sha256': residual.save(name + '.packet', packet),
                    'stderr_sha256': residual.save(name + '.stderr', error),
                    'query_sha256': residual.save(name + '.key', bound),
                    'object_sha256': residual.save(name + '.object.o', open(output, 'rb').read())
                        if os.path.isfile(output) else None}
                result['cases'].append(row)
                print(name, 'native parametric producer', status, flush=True)
        else:
            produced = json.load(open('/transfer-producer/evidence.json'))
            producer_rows = {row['name']: row for row in produced['cases']}
            for recipient in capture['cases']:
                original = open(recipient['source_path'], 'rb').read()
                original_stat = os.stat(recipient['source_path'])
                try:
                    own_source = open('/transfer-capture/' + recipient['name'] + '.source', 'rb').read()
                    own_packet = open('/transfer-producer/' + recipient['name'] + '.packet', 'rb').read()
                    seeds = [case for case in capture['cases'] if case['source'] == recipient['source'] and
                             case['variant'] != 'ast-error-limit']
                    if recipient['variant'] == 'ast-error-limit': seeds.append(recipient)
                    for seed in seeds:
                        open(recipient['source_path'], 'wb').write(own_source)
                        os.utime(recipient['source_path'], (recipient['mtime'], recipient['mtime']))
                        packet = open('/transfer-producer/' + seed['name'] + '.packet', 'rb').read()
                        case = dict(recipient, name=seed['name'] + '-to-' + recipient['variant'])
                        native = residual.request(case, 'native', prior)
                        replay = residual.request(case, 'replay', prior, packet)
                        row = {'name': case['name'], 'seed': seed['name'], 'recipient': recipient['name'],
                            'native': native, 'replay': replay, 'variant': recipient['variant'],
                            'same_computation_key': core(packet)[0] == core(own_packet)[0],
                            'same_full_context_key': producer_rows[seed['name']]['query_sha256'] == producer_rows[recipient['name']]['query_sha256'],
                            'status_and_streams_match': all(native[k] == replay[k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256')),
                            'structural_effects_match': signature(native) == signature(replay),
                            'queued_event_roles_match': queue_signature(native['events']) == queue_signature(replay['events'])}
                        result['cases'].append(row)
                    if recipient['variant'] == 'ast-policy-warning':
                        for fault in ('changed-code', 'corrupt-computation-key'):
                            edit = own_source.replace(b'return a[0];', b'return a[0] + 1;') if fault == 'changed-code' else own_source
                            open(recipient['source_path'], 'wb').write(edit)
                            os.utime(recipient['source_path'], (recipient['mtime'], recipient['mtime']))
                            packet = own_packet
                            if fault == 'corrupt-computation-key':
                                _, offset = core(packet)
                                at = offset + len(core(packet)[0]) - 1
                                packet = packet[:at] + bytes([packet[at] ^ 1]) + packet[at + 1:]
                            case = dict(recipient, name=recipient['name'] + '-' + fault)
                            residual.save(case['name'] + '.submitted.packet', packet)
                            residual.save(case['name'] + '.source', edit)
                            native = residual.request(case, 'native', prior)
                            replay = residual.request(case, 'replay', prior, packet)
                            result['cases'].append({'name': case['name'], 'fault': fault, 'native': native, 'replay': replay,
                                'status_and_streams_match': all(native[k] == replay[k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256')),
                                'structural_effects_match': signature(native) == signature(replay),
                                'queued_event_roles_match': queue_signature(native['events']) == queue_signature(replay['events'])})
                    print(recipient['name'], 'cross-policy comparisons collected', flush=True)
                finally:
                    open(recipient['source_path'], 'wb').write(original)
                    os.utime(recipient['source_path'], ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
    finally:
        with open(ROOT + '/evidence.json', 'w') as stream: json.dump(result, stream, indent=2)


if __name__ == '__main__':
    main(sys.argv[1])
