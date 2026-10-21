"""Trusted Modal recipient entry points, Python 3.5 compatible.

Install under a root-owned directory and start with python -I. Agent code gets
only the exec path after UID/capability reduction and environment selection.
"""

import ctypes
import errno
import json
import os
import subprocess
import sys

sys.path.insert(0, '/rgec-trusted')


TRUSTED = '/rgec-trusted'
RECIPIENT = '/workspace/recipient'
NATIVE_KEYS = ('CC', 'CXX', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS', 'LIB_FUZZING_ENGINE',
               'SRC', 'OUT', 'WORK', 'ARCHITECTURE', 'SANITIZER', 'FUZZING_ENGINE',
               'CXXFLAGS_EXTRA', 'SANITIZER_FLAGS_address', 'COVERAGE_FLAGS',
               'LIBRARY_PATH', 'CCC', 'SOURCE_DATE_EPOCH')
ENV = {key: os.environ[key] for key in NATIVE_KEYS if key in os.environ}
ENV.update(PATH='/usr/local/bin:/usr/bin:/bin', HOME=RECIPIENT, LANG='C', LC_ALL='C')


def drop():
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Word(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32),
                   ('inheritable', ctypes.c_uint32)]
    libc = ctypes.CDLL(None, use_errno=True)
    assert libc.prctl(38, 1, 0, 0, 0) == 0
    for cap in range(41):
        code = libc.prctl(24, cap, 0, 0, 0)
        if code < 0 and ctypes.get_errno() != errno.EINVAL:
            raise OSError(ctypes.get_errno(), 'capability bounding drop failed')
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    header, words = Header(0x20080522, 0), (Word * 2)()
    assert libc.capset(ctypes.byref(header), words) == 0
    assert libc.capget(ctypes.byref(header), words) == 0
    assert not any(getattr(w, field) for w in words for field in ('effective', 'permitted', 'inheritable'))
    bounded = [cap for cap in range(41) if libc.prctl(23, cap, 0, 0, 0) == 1]
    assert not bounded and libc.prctl(39, 0, 0, 0, 0) == 1
    return {'uid': os.getuid(), 'gid': os.getgid(), 'groups': os.getgroups(),
            'capability_words': [{field: getattr(w, field) for field in
                ('effective', 'permitted', 'inheritable')} for w in words],
            'bounding_capabilities': bounded, 'no_new_privs': 1,
            'environment_names': sorted(ENV)}


def native(argv, cwd, timeout=180):
    process = subprocess.Popen(argv, cwd=cwd, preexec_fn=drop, close_fds=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    out, error = process.communicate(timeout=timeout)
    return process.returncode, out, error


def publisher():
    from recipient_effect import EffectIneligible, RecipientOutput
    try:
        ticket = RecipientOutput(RECIPIENT, 'action.o')
    except EffectIneligible as error:
        print(json.dumps({'eligible': False, 'reason': str(error)}), flush=True)
        return
    print(json.dumps({'eligible': True}), flush=True)
    try:
        reply = json.loads(sys.stdin.readline())
        assert set(reply) == {'object_hex'}
        ticket.finish(bytes.fromhex(reply['object_hex']) if reply['object_hex'] is not None else None)
    finally:
        ticket.close()


if __name__ == '__main__':
    mode = sys.argv[1]
    if mode == 'publisher':
        assert os.getuid() == 65534
        publisher()
    else:
        assert os.getuid() == 0, 'only the bound host can invoke the trusted controller'
        if mode == 'exec':
            audit = os.open(TRUSTED + '/actors/' + sys.argv[2] + '.json',
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                row = drop()
                os.write(audit, json.dumps(row).encode())
            finally:
                os.close(audit)
            for value in os.listdir('/proc/self/fd'):
                if int(value) > 2:
                    try:
                        os.close(int(value))
                    except OSError as error:
                        if error.errno != errno.EBADF:
                            raise
            os.chdir('/src/graphicsmagick')
            os.execve('/bin/bash', ['bash', '--noprofile', '--norc', '-c', sys.argv[3]], ENV)
        elif mode == 'capture':
            from modal_recipient_capture import main
            main(sys.argv[2], sys.argv[3])
        else:
            raise ValueError('unknown trusted entry mode')
