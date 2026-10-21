"""Trusted experimental native backend protocol; install root-owned on Modal.

Receipts and lookup stay on the host. Known checks are not closure certificates.
"""
import hashlib
import json
import os
import struct
import subprocess
import sys
import tarfile
import threading

sys.path.insert(0, '/rgec-trusted')
sys.path.insert(0, '/')
from modal_recipient_entry import ENV, RECIPIENT, TRUSTED, drop
from recipient_lease import RecipientLease
from rgec_backend_probe import driver, key, watch, packet_info
from rgec_native_effect_probe import FLAGS, observe
from rgec_native_event_probe import events

PROFILES = {
    'zlib-adler32': ('/src/zlib', 'adler32.c', FLAGS + ['-fPIC']),
    'zlib-deflate': ('/src/zlib', 'deflate.c', FLAGS + ['-fPIC']),
    'fuzzer-util': ('/src/libfuzzer', 'FuzzerUtil.cpp', FLAGS + ['-stdlib=libc++', '-std=c++11']),
}
PROFILES.update({name + '-parametric': (cwd, source, flags + ['-Wframe-larger-than=1'])
                 for name, (cwd, source, flags) in list(PROFILES.items())})
PROFILES.update({name + '-nested': PROFILES[name] for name in
                 ('zlib-adler32', 'zlib-deflate', 'fuzzer-util')})
PROFILES.update({name + '-rewrite': (cwd, source, flags + ['-Wframe-larger-than=1',
    '-frewrite-map-file', RECIPIENT + '/rewrite-map.yaml'])
    for name, (cwd, source, flags) in list(PROFILES.items())
    if name in ('zlib-adler32', 'zlib-deflate', 'fuzzer-util')})


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main(profile, identity, mode):
    assert os.getuid() == 0 and mode in ('native', 'replay', 'record')
    cwd, source, flags = PROFILES[profile]
    directory = TRUSTED + '/requests/' + identity
    os.mkdir(directory, 0o700)
    output = RECIPIENT + ('/missing/action.o' if profile.endswith('-nested') else '/action.o')
    paths = [output, RECIPIENT + '/alias.o', RECIPIENT + '/target.o']
    lease = RecipientLease().acquire()
    process, fd, held = None, None, None
    try:
        argv = ['/usr/local/bin/clang++' if source.endswith('.cpp') else '/usr/local/bin/clang'] + flags + ['-c', source, '-o', output]
        if mode != 'native':
            argv = driver(argv, cwd)
        row = {'profile': profile, 'mode': mode, 'paths': paths,
               'before': {path: observe(path) for path in paths},
               'lease_audit': lease.audit, 'stopped_actors': lease.stopped,
               'environment': ENV, 'query_emitted': False}
        if os.path.isfile(output):
            held = os.open(output, os.O_RDONLY)
        fd = watch(RECIPIENT)
        env = dict(ENV)
        if mode != 'native':
            env['RGEC_BACKEND_MODE'] = mode
        executable = '/usr/local/bin/clang' if mode != 'native' else None
        process = subprocess.Popen(argv, executable=executable, cwd=cwd, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=drop, close_fds=True)
        diagnostics = []
        reader = threading.Thread(target=lambda: diagnostics.append(process.stderr.read()))
        reader.start()
        prefix = b''
        if mode == 'replay':
            prefix = process.stdout.read(6)
            if prefix == b'RGECQ1':
                length_bytes = process.stdout.read(8)
                assert len(length_bytes) == 8
                length = struct.unpack('<Q', length_bytes)[0]
                assert length <= 128 * 1024 * 1024
                bound = process.stdout.read(length)
                assert len(bound) == length
                prefix += length_bytes + bound
                with open(directory + '/query.bin', 'wb') as stream:
                    stream.write(bound)
                row['query_emitted'] = True
                print(json.dumps({'phase': 'query', 'key_sha256': sha(bound), 'key_bytes': length}), flush=True)
                assert json.loads(sys.stdin.readline()) == {'op': 'continue'}
                with open(directory + '/reply.packet', 'rb') as stream:
                    packet = stream.read(128 * 1024 * 1024 + 1)
                assert len(packet) <= 128 * 1024 * 1024
                process.stdin.write(packet)
                process.stdin.flush()
        process.stdin.close()
        control = prefix + process.stdout.read()
        process.wait(timeout=180); reader.join(timeout=10)
        assert not reader.is_alive()
        diagnostic = diagnostics[0]
        bound, receipt = key(control) if mode == 'replay' else (None, control)
        queued = events(fd)
        fd = None  # events consumes and closes the watcher.
        row.update(returncode=process.returncode,
            after={path: observe(path) for path in paths}, events=queued,
            directory_entries_after=sorted(os.listdir(RECIPIENT)),
            stdout_sha256=sha(control if mode == 'native' else b''),
            stderr_sha256=sha(diagnostic), control_sha256=sha(control),
            receipt=receipt.decode() if mode == 'replay' else '',
            key_sha256=sha(bound) if bound is not None else None)
        if held is not None:
            contents = os.read(held, 10000000)
            row['held_fd_content_sha256'] = sha(contents)
            with open(directory + '/held.o', 'wb') as stream:
                stream.write(contents)
        for name, data in (('result.stdout', control if mode == 'native' else b''),
                           ('result.stderr', diagnostic), ('control.bin', control)):
            with open(directory + '/' + name, 'wb') as stream:
                stream.write(data)
        for role, path in zip(('output', 'alias', 'target'), paths):
            if os.path.isfile(path):
                with open(path, 'rb') as stream:
                    contents = stream.read()
                with open(directory + '/' + role + '.o', 'wb') as stream:
                    stream.write(contents)
        if mode == 'record':
            row['packet_info'] = packet_info(control)
            with open(directory + '/record.packet', 'wb') as stream:
                stream.write(control)
    finally:
        if process and process.poll() is None:
            process.kill(); process.wait()
        if fd is not None:
            os.close(fd)
        if held is not None:
            os.close(held)
        lease.release()
    with open(directory + '/trace.json', 'w') as stream:
        json.dump(row, stream, indent=2)
    archive = directory + '.tar.gz'
    with tarfile.open(archive, 'w:gz') as stream:
        for name in sorted(os.listdir(directory)):
            stream.add(directory + '/' + name, arcname=name)
    print(json.dumps({'phase': 'finished', 'returncode': row['returncode'],
        'archive_sha256': sha(open(archive, 'rb').read())}), flush=True)


if __name__ == '__main__':
    main(*sys.argv[1:])
