"""Blocked real compiler cost measurements; no local or mocked compilation."""
import json
import os
import random
import resource
import statistics
import struct
import sys
import time

sys.path.insert(0, '/')
import rgec_residual_probe as residual
from rgec_backend_probe import ROOT, packet_info, reset, run, queue_signature
from rgec_native_effect_probe import FLAGS, sha, signature


def measure(function):
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    start = time.perf_counter()
    result = function()
    elapsed = time.perf_counter() - start
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    return result, {'wall_seconds': elapsed, 'children_user_seconds': after.ru_utime - before.ru_utime,
        'children_system_seconds': after.ru_stime - before.ru_stime,
        'children_cpu_seconds': after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime}


def main():
    os.mkdir(ROOT); os.chown(ROOT, 65534, 65534)
    modes = ['native', 'record', 'replay-full', 'replay-compact']
    result = {'cases': [], 'blocks_per_source': 6, 'randomization_seed': 1729, 'measured_modes': modes,
        'metric_scope': 'Sequential single-sandbox child-process CPU and total helper wall time. Wrapped paths include two actual native -### driver checks. Artifact hashing/watching is included in wall time. Host authentication, network transfer, full builds, release padding and cross-agent contention are excluded.',
        'noninterference_proved': False, 'full_system_compute_saving_established': False}
    generator = random.Random(result['randomization_seed'])
    status, _, error = run(['/usr/local/bin/clang'] + FLAGS +
        ['-fPIC', '-c', 'deflate.c', '-o', ROOT + '/prior.o'], '/src/zlib')
    assert status == 0, error
    prior = open(ROOT + '/prior.o', 'rb').read()
    try:
        for path in ('/src/zlib/adler32.c', '/src/zlib/deflate.c', '/src/libfuzzer/FuzzerUtil.cpp'):
            original = open(path, 'rb').read()
            case = {'name': os.path.basename(path) + '-cost', 'source': os.path.basename(path),
                'source_path': path, 'cwd': os.path.dirname(path), 'source_sha256': residual.save(os.path.basename(path) + '.original', original),
                'compiler': '/usr/local/bin/clang++' if path.endswith('.cpp') else '/usr/local/bin/clang',
                'flags': FLAGS + (['-stdlib=libc++', '-std=c++11'] if path.endswith('.cpp') else ['-fPIC']) + ['-Wframe-larger-than=1']}
            native = residual.request(dict(case, name=case['name'] + '-prime'), 'native', prior)
            capture = residual.request(dict(case, name=case['name'] + '-capture'), 'record', prior)
            assert all(native[k] == capture[k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256', 'object_sha256'))
            bound = open(ROOT + '/' + case['name'] + '-capture.key', 'rb').read()
            reset(ROOT + '/action-' + case['source'], 'hardlink', prior)
            production, producer_cost = measure(lambda: run(['/rgec-backend', '--rgec-produce-parametric'], case['cwd'], None, bound))
            status, packet, error = production
            assert status == 0, error
            info = packet_info(packet)
            assert info['reusable'] and info['key_sha256'] == sha(bound)
            producer_packet_sha256 = residual.save(case['name'] + '.producer.packet', packet)
            producer_stderr_sha256 = residual.save(case['name'] + '.producer.stderr', error)
            producer_object_sha256 = residual.save(case['name'] + '.producer.object.o', open(ROOT + '/action-' + case['source'] + '/action.o', 'rb').read())
            assert producer_object_sha256 == native['object_sha256']
            assert packet.startswith(b'RGECB2')
            full_size = struct.unpack_from('<Q', packet, 6)[0]
            compact_packet = b'RGECB3' + packet[14 + full_size:]
            compact_packet_sha256 = residual.save(case['name'] + '.compact.packet', compact_packet)
            compact_info = packet_info(compact_packet)
            assert compact_info['operations'] == info['operations']
            assert compact_info['computation_key_sha256'] == info['computation_key_sha256']
            measured = []
            for block in range(result['blocks_per_source']):
                order = list(modes); generator.shuffle(order)
                for position, mode in enumerate(order):
                    own = dict(case, name=case['name'] + '-block-' + str(block) + '-' + str(position))
                    compiler_mode = 'replay' if mode.startswith('replay-') else mode
                    delivered = compact_packet if mode == 'replay-compact' else packet if mode == 'replay-full' else None
                    observation, metrics = measure(lambda: residual.request(own, compiler_mode, prior, delivered))
                    assert all(native[k] == observation[k] for k in ('returncode', 'stdout_sha256', 'stderr_sha256', 'object_sha256'))
                    assert signature(native) == signature(observation)
                    assert queue_signature(native['events']) == queue_signature(observation['events'])
                    if compiler_mode == 'replay': assert observation['receipt'] == 'RGECH1'
                    measured.append({'block': block, 'position': position, 'mode': mode,
                        'metrics': metrics, 'observation': observation})
            medians = {mode: {metric: statistics.median(r['metrics'][metric] for r in measured if r['mode'] == mode)
                for metric in ('wall_seconds', 'children_cpu_seconds')} for mode in modes}
            result['cases'].append(dict(case, native_prime=native, capture=capture,
                producer_status=status, producer_cost=producer_cost, producer_info=info,
                producer_packet_bytes=len(packet), producer_packet_sha256=producer_packet_sha256,
                compact_packet_bytes=len(compact_packet), compact_packet_sha256=compact_packet_sha256,
                compact_info=compact_info,
                producer_stderr_sha256=producer_stderr_sha256, producer_object_sha256=producer_object_sha256,
                observations=measured, medians=medians, source_unchanged=open(path, 'rb').read() == original))
            assert open(path, 'rb').read() == original
            print(case['source'], json.dumps(medians), flush=True)
    finally:
        with open(ROOT + '/evidence.json', 'w') as stream: json.dump(result, stream, indent=2)


if __name__ == '__main__': main()
