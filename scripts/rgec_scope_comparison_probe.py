"""Actual native context-scope comparison; run only in a private Modal worker."""
import json
import os
import random
import resource
import shutil
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, '/')
from backend_recipe_store import BackendRecipeStore, computation_key
from modal_recipient_entry import ENV, drop
from rgec_backend_probe import key, watch
from rgec_native_effect_probe import observe, setup, sha, signature
from rgec_native_event_probe import events

ROOT = '/rgec-private/scope'
RECIPIENT = '/workspace/recipient'


def main(blocks):
    assert os.getuid() == 0
    preload = json.load(open(ROOT + '/preload.json'))
    result = {'rows': [], 'planned_order': [], 'seed': 6421,
        'scope': 'Three real existing functions, two native warning histories; seeded stores, native misses without cache filling. No admission certificate or fixed release.',
        'complete_closure_certified': False, 'adaptive_noninterference_proved': False}
    def save(name, data):
        with open(ROOT + '/' + name, 'wb') as stream: stream.write(data)
        return sha(data)
    def missing(profile, bound):
        raise RuntimeError('Unexpected computation-key miss: ' + profile)
    store = BackendRecipeStore(preload['context'], missing)
    for item in preload['profiles']:
        packet = bytes.fromhex(item['delivery_hex'])
        receipt = item['receipt']
        assert sha(packet) == receipt['packet_sha256']
        store.entries[(item['profile'], receipt['key_sha256'])] = (receipt, packet, store._tag(receipt))
    randomizer = random.Random(result['seed'])
    for item in preload['profiles']:
        for block in range(blocks):
            order = [(history, mode) for history in ('ignored', 'warning')
                     for mode in ('native', 'full-context', 'computation')]
            randomizer.shuffle(order)
            for history, mode in order:
                result['planned_order'].append({'profile': item['profile'], 'block': block,
                                               'history': history, 'mode': mode})
    profiles = {item['profile']: item for item in preload['profiles']}
    for planned in result['planned_order']:
        item = profiles[planned['profile']]
        source = item['cwd'] + '/' + item['source']
        contents = bytes.fromhex(item[planned['history'] + '_source_hex'])
        with open(source, 'wb') as stream: stream.write(contents)
        os.utime(source, (1641013200, 1641013200))
        if os.path.exists(RECIPIENT): shutil.rmtree(RECIPIENT)
        setup(RECIPIENT, 'hardlink', bytes.fromhex(preload['prior_hex']))
        with open(RECIPIENT + '/rewrite-map.yaml', 'wb') as stream:
            stream.write(bytes.fromhex(item['map_hex']))
        os.chmod(RECIPIENT + '/rewrite-map.yaml', 0o644)
        label = 'action-' + str(len(result['rows'])).zfill(3)
        paths = [RECIPIENT + '/action.o', RECIPIENT + '/alias.o', RECIPIENT + '/target.o']
        row = dict(planned, label=label, paths=paths, source_sha256=sha(contents),
                   before={path: observe(path) for path in paths}, query_emitted=False)
        result['rows'].append(row)
        held = os.open(paths[0], os.O_RDONLY)
        fd = watch(RECIPIENT)
        env = dict(ENV)
        replay = planned['mode'] != 'native'
        if replay: env['RGEC_BACKEND_MODE'] = 'replay'
        argv = ['/rgec-backend' if replay else '/usr/local/bin/clang', '-cc1'] + item['arguments']
        row['argv'] = argv
        child_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        self_before = resource.getrusage(resource.RUSAGE_SELF)
        start = time.monotonic()
        process = subprocess.Popen(argv, cwd=item['cwd'], env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, preexec_fn=drop)
        diagnostics = []
        reader = threading.Thread(target=lambda: diagnostics.append(process.stderr.read()))
        reader.start()
        prefix = b''
        try:
            if replay:
                prefix = process.stdout.read(6)
                assert prefix == b'RGECQ1', prefix
                size_bytes = process.stdout.read(8)
                assert len(size_bytes) == 8
                size = struct.unpack('<Q', size_bytes)[0]
                assert size <= 128 * 1024 * 1024
                bound = process.stdout.read(size)
                assert len(bound) == size
                prefix += size_bytes + bound
                row['query_emitted'] = True
                row['query_sha256'] = save(label + '.query', bound)
                row['computation_sha256'] = sha(computation_key(bound))
                assert row['computation_sha256'] == item['receipt']['key_sha256']
                if planned['mode'] == 'full-context' and sha(bound) != item['full_context_sha256']:
                    packet = b''
                    row['store_route'] = 'scope-miss-native-computation'
                else:
                    packet = store.resolve(item['profile'], bound)
                    row['store_route'] = store.audit[-1]['route']
                row['reply_sha256'] = save(label + '.reply', packet)
                process.stdin.write(packet); process.stdin.flush()
            process.stdin.close()
            control = prefix + process.stdout.read()
            process.wait(timeout=180); reader.join(10)
            assert not reader.is_alive()
            row['helper_wall_seconds'] = time.monotonic() - start
            child_after = resource.getrusage(resource.RUSAGE_CHILDREN)
            self_after = resource.getrusage(resource.RUSAGE_SELF)
            row['child_cpu_seconds'] = child_after.ru_utime + child_after.ru_stime - child_before.ru_utime - child_before.ru_stime
            row['service_cpu_seconds'] = self_after.ru_utime + self_after.ru_stime - self_before.ru_utime - self_before.ru_stime
            _, receipt = key(control) if replay else (None, b'')
            row.update(returncode=process.returncode, receipt=receipt.decode(),
                stdout_sha256=save(label + '.stdout', b'' if replay else control),
                stderr_sha256=save(label + '.stderr', diagnostics[0]),
                control_sha256=save(label + '.control', control),
                after={path: observe(path) for path in paths}, events=events(fd),
                directory_entries_after=sorted(os.listdir(RECIPIENT)))
            fd = None
            row['held_fd_content_sha256'] = save(label + '.held', os.read(held, 10000000))
            for role, path in zip(('output', 'alias'), paths):
                save(label + '.' + role, open(path, 'rb').read())
            assert row['returncode'] == 0
            if replay:
                expected = 'RGECF1' if row['store_route'] == 'scope-miss-native-computation' else 'RGECH1'
                assert row['receipt'] == expected, row
        finally:
            if process.poll() is None: process.kill(); process.wait()
            if fd is not None: os.close(fd)
            os.close(held)
            save('evidence.json', (json.dumps(result, indent=2) + '\n').encode())
        print(json.dumps({name: row.get(name) for name in
            ('label', 'profile', 'history', 'mode', 'store_route', 'receipt', 'returncode')}), flush=True)
    for row in result['rows']:
        reference = next(other for other in result['rows'] if other['profile'] == row['profile']
            and other['block'] == row['block'] and other['history'] == row['history'] and other['mode'] == 'native')
        assert all(row[name] == reference[name] for name in ('returncode', 'stdout_sha256', 'stderr_sha256'))
        assert signature(row) == signature(reference)
        from rgec_backend_probe import queue_signature
        assert queue_signature(row['events']) == queue_signature(reference['events'])
    save('evidence.json', (json.dumps(result, indent=2) + '\n').encode())


if __name__ == '__main__': main(int(sys.argv[1]))
