"""Real native source/object mutation and lease experiment on Modal only."""

import ctypes
import json
import os
import shutil
import signal
import subprocess
import time

from recipient_lease import RecipientLease, actor_snapshot
from rgec_native_effect_probe import FLAGS, command, drop_authority, sha


ROOT = '/workspace/recipient-lease'


ACTOR = r'''
import os,sys,threading,time
root,mode=sys.argv[1:]
if mode == 'daemon':
    if os.fork(): os._exit(0)
    os.setsid()
with open(root+'/'+mode+'.pid','w') as stream:
    stream.write(str(os.getpid()))
if mode == 'daemon':
    source=os.open(root+'/zlib/adler32.c',os.O_WRONLY|os.O_APPEND)
    held=os.open(root+'/action.o',os.O_RDWR)
    def mutate_source():
        while True:
            os.write(source,b'\n/* real recipient source edit */\n')
            time.sleep(0.02)
    threading.Thread(target=mutate_source,daemon=True).start()
    count=0
    while True:
        os.lseek(held,0,os.SEEK_SET)
        os.write(held,bytes([count%251]))
        count+=1
        time.sleep(0.02)
else:
    with open(root+'/preexisting-stopped-edits','ab',buffering=0) as stream:
        while True:
            stream.write(b'edit\n')
            time.sleep(0.02)
'''


def digest(path):
    with open(path, 'rb') as stream:
        return sha(stream.read())


def main():
    os.chmod('/workspace', 0o755)
    os.mkdir(ROOT)
    shutil.copytree('/src/zlib', ROOT + '/zlib')
    for directory, _, files in os.walk(ROOT):
        os.chown(directory, 65534, 65534)
        for name in files:
            os.chown(directory + '/' + name, 65534, 65534)
    evidence = {'platform': 'Modal', 'shared_reuse_enabled': False,
                'host_new_untrusted_exec_during_lease': 0,
                'full_lease_or_noninterference_certified': False, 'stages': []}
    lease, actors, kill_handles = None, [], []
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    try:
        code, out, error = command(['/usr/local/bin/clang'] + FLAGS +
             ['-fPIC', '-c', 'adler32.c', '-o', ROOT + '/action.o'], ROOT + '/zlib')
        assert code == 0, error
        with open(ROOT + '/fixture.stderr', 'wb') as stream:
            stream.write(error)
        evidence['native_fixture_sha256'] = digest(ROOT + '/action.o')
        os.link(ROOT + '/action.o', ROOT + '/held-alias.o')
        for mode in ('daemon', 'preexisting-stopped'):
            process = subprocess.Popen(['/usr/bin/python3', '-c', ACTOR, ROOT, mode],
                preexec_fn=drop_authority, start_new_session=True, close_fds=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            actors.append(process)
            deadline = time.monotonic() + 5
            while not os.path.exists(ROOT + '/' + mode + '.pid'):
                assert time.monotonic() < deadline, mode
                time.sleep(0.02)
            with open(ROOT + '/' + mode + '.pid') as stream:
                pid = int(stream.read())
            fd = libc.syscall(434, pid, 0)
            assert fd >= 0, ctypes.get_errno()
            kill_handles.append(fd)
            if mode == 'daemon':
                assert process.wait(timeout=5) == 0
                evidence['daemon_identity'] = {'seed_pid': process.pid, 'daemon_pid': pid,
                    'daemon_group': actor_snapshot()[pid]['group']}
            else:
                assert libc.syscall(424, fd, signal.SIGSTOP, 0, 0) == 0
                deadline = time.monotonic() + 5
                while actor_snapshot()[pid]['threads'][pid] != 'T':
                    assert time.monotonic() < deadline
                    time.sleep(0.01)
                evidence['preexisting_stopped_pid'] = pid
        source = ROOT + '/zlib/adler32.c'
        before = os.stat(source).st_size
        time.sleep(0.2)
        evidence['unleased_source_edits_observed'] = os.stat(source).st_size > before
        assert evidence['unleased_source_edits_observed']
        assert evidence['daemon_identity']['daemon_group'] != evidence['daemon_identity']['seed_pid']
        # Existing native file descriptors retain write access after chmod.
        os.chmod(source, 0o444)
        os.chmod(ROOT + '/action.o', 0o444)
        readonly_size = os.stat(source).st_size
        readonly_object = digest(ROOT + '/held-alias.o')
        time.sleep(0.15)
        evidence['readonly_modes_did_not_stop_held_writers'] = (
            os.stat(source).st_size > readonly_size and digest(ROOT + '/held-alias.o') != readonly_object)
        assert evidence['readonly_modes_did_not_stop_held_writers']
        os.chmod(source, 0o644)
        os.chmod(ROOT + '/action.o', 0o644)
        evidence['stages'].append('real source/object writers active outside original group')
        lease = RecipientLease().acquire()
        evidence['lease_audit'] = lease.audit
        evidence['stopped_actors'] = lease.stopped
        frozen_source = digest(source)
        frozen_alias = digest(ROOT + '/held-alias.o')
        stopped_file = ROOT + '/preexisting-stopped-edits'
        stopped_before = digest(stopped_file) if os.path.exists(stopped_file) else None
        time.sleep(0.3)
        evidence['source_and_held_object_stable_during_lease'] = (
            frozen_source == digest(source) and frozen_alias == digest(ROOT + '/held-alias.o'))
        assert evidence['source_and_held_object_stable_during_lease']
        # This is a trusted, newly launched native compiler in a lease fixture.
        # An integrated cache must compute in a separate sealed backend.
        code, out, error = command(['/usr/local/bin/clang'] + FLAGS +
             ['-fPIC', '-c', 'adler32.c', '-o', ROOT + '/native-lease.o'], ROOT + '/zlib')
        evidence['leased_native_compile_returncode'] = code
        with open(ROOT + '/leased-native.stdout', 'wb') as stream:
            stream.write(out)
        with open(ROOT + '/leased-native.stderr', 'wb') as stream:
            stream.write(error)
        assert code == 0, error
        helper = "from recipient_effect import RecipientOutput; " \
                 "r=RecipientOutput(" + repr(ROOT) + ",'action.o'); " \
                 "r.finish(open(" + repr(ROOT + '/native-lease.o') + ",'rb').read())"
        code, out, error = command(['/usr/bin/python3', '-c', helper], '/')
        evidence['recipient_finish_returncode'] = code
        with open(ROOT + '/recipient-finish.stderr', 'wb') as stream:
            stream.write(error)
        assert code == 0, error
        expected = digest(ROOT + '/native-lease.o')
        evidence['recipient_native_object_sha256'] = expected
        assert digest(ROOT + '/action.o') == expected
        shutil.copyfile(ROOT + '/action.o', ROOT + '/success-output.o')
        assert digest(source) == frozen_source
        assert digest(ROOT + '/held-alias.o') == frozen_alias
        evidence['stages'].append('native compile and recipient output under stopped actors')
        lease.release()
        lease = None
        time.sleep(0.25)
        evidence['resumed_source_edits_observed'] = digest(source) != frozen_source
        evidence['resumed_held_inode_edits_observed'] = digest(ROOT + '/held-alias.o') != frozen_alias
        evidence['replacement_output_unchanged_after_resume'] = digest(ROOT + '/action.o') == expected
        pid = evidence['preexisting_stopped_pid']
        evidence['preexisting_stop_preserved'] = actor_snapshot()[pid]['threads'][pid] == 'T'
        evidence['preexisting_stopped_file_unchanged'] = (
            (digest(stopped_file) if os.path.exists(stopped_file) else None) == stopped_before)
        assert all(evidence[field] for field in ('resumed_source_edits_observed',
            'resumed_held_inode_edits_observed', 'replacement_output_unchanged_after_resume',
            'preexisting_stop_preserved', 'preexisting_stopped_file_unchanged'))
        evidence['stages'].append('resume and held-inode/previous-stop checks passed')
        lease = RecipientLease().acquire()
        with open(source, 'rb') as stream:
            valid_source = stream.read()
        with open(source, 'ab') as stream:
            stream.write(b'\n#error RGEC actual native failure under recipient lease\n')
        try:
            code, out, error = command(['/usr/local/bin/clang'] + FLAGS +
                ['-fPIC', '-c', 'adler32.c', '-o', ROOT + '/native-lease.o'], ROOT + '/zlib')
            evidence['leased_native_failure_returncode'] = code
            with open(ROOT + '/leased-failure.stdout', 'wb') as stream:
                stream.write(out)
            with open(ROOT + '/leased-failure.stderr', 'wb') as stream:
                stream.write(error)
            assert code == 1 and not os.path.exists(ROOT + '/native-lease.o'), error
            helper = "from recipient_effect import RecipientOutput; " \
                     "r=RecipientOutput(" + repr(ROOT) + ",'action.o'); r.finish(None)"
            code, out, error = command(['/usr/bin/python3', '-c', helper], '/')
            evidence['failure_recipient_finish_returncode'] = code
            assert code == 0, error
            evidence['native_and_recipient_failure_removed_outputs'] = not os.path.exists(ROOT + '/action.o')
            assert evidence['native_and_recipient_failure_removed_outputs']
        finally:
            with open(source, 'wb') as stream:
                stream.write(valid_source)
            lease.release()
            lease = None
        before = os.stat(source).st_size
        time.sleep(0.15)
        evidence['writers_resumed_after_native_failure'] = os.stat(source).st_size > before
        evidence['preexisting_stop_preserved_after_failure'] = actor_snapshot()[pid]['threads'][pid] == 'T'
        assert evidence['writers_resumed_after_native_failure'] and evidence['preexisting_stop_preserved_after_failure']
        evidence['stages'].append('actual native failure cleanup and lease release passed')
    except Exception as error:
        evidence['error'] = str(error)
        raise
    finally:
        if lease:
            lease.release()
        for fd in kill_handles:
            result = libc.syscall(424, fd, signal.SIGKILL, 0, 0)
            os.close(fd)
        for process in actors:
            process.wait(timeout=5)
        with open(ROOT + '/evidence.json', 'w') as stream:
            json.dump(evidence, stream, indent=2)
    print(json.dumps(evidence, indent=2), flush=True)


if __name__ == '__main__':
    main()
