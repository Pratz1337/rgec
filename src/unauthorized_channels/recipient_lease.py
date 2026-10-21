"""Experimental UID-scoped recipient stop lease, Python 3.5 compatible.

The trusted host must block new untrusted exec for the whole lease. Existing
actors must share UID 65534 in this private PID namespace. This does not drain
in-flight kernel I/O or certify contextual filesystem equivalence.
"""

import ctypes
import errno
import os
import signal
import time

if __package__:
    from .recipient_effect import EffectIneligible
else:
    from recipient_effect import EffectIneligible


def status(path):
    with open(path + '/status') as stream:
        return dict(line.rstrip().split(':', 1) for line in stream if ':' in line)


def actor_snapshot():
    actors = {}
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        path = '/proc/' + entry
        try:
            row = status(path)
            uids = [int(value) for value in row['Uid'].split()]
            if 65534 not in uids or row['State'].strip().startswith('Z'):
                continue
            if uids != [65534] * 4 or int(row['TracerPid']) or int(row['NoNewPrivs']) != 1:
                raise EffectIneligible('unsupported recipient identity or tracer')
            for field in ('CapEff', 'CapPrm', 'CapInh'):
                if int(row[field], 16):
                    raise EffectIneligible('recipient retains capabilities')
            threads = {int(tid): status(path + '/task/' + tid)['State'].strip().split()[0]
                       for tid in os.listdir(path + '/task')}
            if 't' in threads.values():
                raise EffectIneligible('ptrace stop is unsupported')
            with open(path + '/stat') as stream:
                fields = stream.read().rsplit(')', 1)[1].split()
            actors[int(entry)] = {'uids': uids, 'starttime': fields[19],
                                  'threads': threads, 'group': int(fields[2])}
        except OSError as error:
            if error.errno not in (errno.ENOENT, errno.ESRCH):
                raise
    return actors


class RecipientLease:
    def __init__(self):
        self.handles = {}
        self.audit = []
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long
        if os.getuid() != 0 or os.uname().machine != 'x86_64':
            raise EffectIneligible('lease requires the trusted x86_64 controller')

    def signal(self, fd, value):
        if self.libc.syscall(424, fd, value, 0, 0) < 0:
            code = ctypes.get_errno()
            if code != errno.ESRCH:
                raise OSError(code, os.strerror(code))

    def acquire(self):
        """Call before cache lookup, while host agent-exec admission is closed."""
        deadline = time.monotonic() + 5
        try:
            while time.monotonic() < deadline:
                actors = actor_snapshot()
                for pid, row in actors.items():
                    if pid not in self.handles:
                        fd = self.libc.syscall(434, pid, 0)
                        if fd < 0:
                            code = ctypes.get_errno()
                            if code == errno.ESRCH:
                                continue
                            raise EffectIneligible('pidfd_open: ' + os.strerror(code))
                        # A held descriptor signals its original process even if
                        # that process exits. Check that its live PID still has
                        # the classified UID/start time before using it.
                        self.handles[pid] = {'fd': fd, 'resume': False}
                        check = actor_snapshot().get(pid)
                        with open('/proc/self/fdinfo/' + str(fd)) as stream:
                            fdinfo = dict(line.rstrip().split(':', 1) for line in stream if ':' in line)
                        if int(fdinfo['Pid']) != pid or not check or check['starttime'] != row['starttime']:
                            raise EffectIneligible('recipient changed during identity binding')
                        self.audit.append(dict(pid=pid, before=check))
                        self.handles[pid]['resume'] = any(s != 'T' for s in check['threads'].values())
                    if any(s != 'T' for s in row['threads'].values()):
                        self.signal(self.handles[pid]['fd'], signal.SIGSTOP)
                after = actor_snapshot()
                if set(after).issubset(self.handles) and all(
                        all(s == 'T' for s in row['threads'].values()) for row in after.values()):
                    self.stopped = after
                    return self
                time.sleep(0.01)
            raise EffectIneligible('recipient did not stop within the lease bound')
        except Exception:
            self.release()
            raise

    def release(self):
        errors = []
        for row in self.handles.values():
            try:
                if row['resume']:
                    self.signal(row['fd'], signal.SIGCONT)
            except OSError as error:
                errors.append(str(error))
            finally:
                os.close(row['fd'])
        self.handles.clear()
        if errors:
            raise EffectIneligible('lease release failed: ' + '; '.join(errors))
