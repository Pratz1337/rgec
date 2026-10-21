"""Real queued inotify observations of Clang and the recipient residual."""

import ctypes
import json
import os
import struct
import sys

from rgec_native_effect_probe import FLAGS, command, observe, sha


ROOT = '/workspace/event-effects'


def watch():
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    assert fd >= 0, ctypes.get_errno()
    mask = 0x2 | 0x4 | 0x8 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200
    assert libc.inotify_add_watch(fd, ROOT.encode(), mask) >= 0, ctypes.get_errno()
    return fd


def events(fd):
    rows = []
    while True:
        try:
            data = os.read(fd, 65536)
        except BlockingIOError:
            break
        offset = 0
        while offset < len(data):
            wd, mask, cookie, length = struct.unpack_from('iIII', data, offset)
            name = data[offset + 16:offset + 16 + length].split(b'\0')[0].decode()
            rows.append({'mask': mask, 'cookie': cookie, 'name': name})
            offset += 16 + length
    os.close(fd)
    return rows


def main():
    os.chmod('/workspace', 0o755)
    os.mkdir(ROOT)
    os.chown(ROOT, 65534, 65534)
    compiler = ['/usr/local/bin/clang'] + FLAGS + ['-fPIC', '-c', 'deflate.c', '-o', ROOT + '/prior.o']
    code, _, error = command(compiler, '/src/zlib')
    assert code == 0, error
    with open(ROOT + '/prior.o', 'rb') as stream:
        prior = stream.read()
    source = '/src/zlib/adler32.c'
    with open(source, 'rb') as stream:
        original = stream.read()
    rows = []
    try:
        for failed in (False, True):
            with open(source, 'wb') as stream:
                stream.write(original + b'\n#error RGEC real-source failure control\n' if failed else original)
            for mode in ('native', 'recipient'):
                with open(ROOT + '/action.o', 'wb') as stream:
                    stream.write(prior)
                os.chown(ROOT + '/action.o', 65534, 65534)
                os.chmod(ROOT + '/action.o', 0o600)
                fd = watch()
                if mode == 'native':
                    code, out, error = command(['/usr/local/bin/clang'] + FLAGS +
                        ['-fPIC', '-c', 'adler32.c', '-o', ROOT + '/action.o'], '/src/zlib')
                else:
                    script = 'import sys; sys.path.insert(0,"/"); from recipient_effect import RecipientOutput; r=RecipientOutput(' + repr(ROOT) + \
                             ',"action.o"); r.finish(' + ('None' if failed else 'open("/workspace/payload.o","rb").read()') + ')'
                    code, out, error = command(['/usr/bin/python3', '-c', script], '/src/zlib')
                observed_events = events(fd)
                state = observe(ROOT + '/action.o')
                if mode == 'native' and not failed:
                    with open(ROOT + '/action.o', 'rb') as stream:
                        payload = stream.read()
                    with open('/workspace/payload.o', 'wb') as stream:
                        stream.write(payload)
                rows.append({'mode': mode, 'source_failure': failed, 'process_returncode': code,
                             'events': observed_events, 'output_after': state,
                             'stdout_sha256': sha(out), 'stderr_sha256': sha(error),
                             'stdout_hex': out.hex(), 'stderr_hex': error.hex()})
    finally:
        with open(source, 'wb') as stream:
            stream.write(original)
    evidence = {'rows': rows, 'observation': 'actual inotify queue consumed after action completion',
                'note': 'Recipient helper status is effect-operation status, not compiler payload status.',
                'recipient_helpers_valid': all(r['process_returncode'] == 0 for r in rows if r['mode'] == 'recipient'),
                'shared_reuse_enabled': False, 'full_trace_equivalence_certified': False}
    with open('/event-evidence.json', 'w') as stream:
        json.dump(evidence, stream, indent=2)
    assert evidence['recipient_helpers_valid'], 'recipient effect helper failed'


if __name__ == '__main__':
    main()
