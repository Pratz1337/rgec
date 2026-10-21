"""Trusted native launcher for Modal: private chroot, DAC and dropped authority.

No Landlock or Docker-in-Docker assumption. Live clocks remain unclosed.
Python 3.5 compatible for the authentic ARVO toolchain image.
"""

import ctypes
import errno
import json
import os


class CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]


def checked(result):
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


if __name__ == "__main__":
    with open("/rgec-action.json") as stream:
        action = json.load(stream)
    libc = ctypes.CDLL(None, use_errno=True)
    root = "/rgec-root"
    os.mkdir(root + "/output", 0o700)
    os.chown(root + "/output", 65534, 65534)
    checked(libc.prctl(38, 1, 0, 0, 0))  # PR_SET_NO_NEW_PRIVS
    # A directory fd retained from outside the root could defeat pathname
    # confinement. Only the authorized standard streams survive this boundary.
    inherited = [int(fd) for fd in os.listdir('/proc/self/fd') if int(fd) > 2]
    for fd in inherited:
        try:
            os.close(fd)
        except OSError as error:
            if error.errno != errno.EBADF:  # listdir's temporary fd is closed already
                raise
    os.chroot(root)
    os.chdir(action["cwd"])
    for cap in range(41):
        result = libc.prctl(24, cap, 0, 0, 0)  # PR_CAPBSET_DROP
        if result < 0 and ctypes.get_errno() != errno.EINVAL:
            checked(result)
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    header, data = CapHeader(0x20080522, 0), (CapData * 2)()
    # gVisor did not clear every capability word on the tested UID transition.
    # Reduce explicitly, then verify; never infer authority from UID alone.
    checked(libc.capset(ctypes.byref(header), data))
    checked(libc.capget(ctypes.byref(header), data))
    caps = [{field: getattr(word, field) for field in ("effective", "permitted", "inheritable")}
            for word in data]
    if any(value for word in caps for value in word.values()):
        raise RuntimeError("compiler retained process capabilities")
    bounded = [cap for cap in range(41) if libc.prctl(23, cap, 0, 0, 0) == 1]
    if bounded:
        raise RuntimeError("compiler retained bounding capabilities")
    nnp = checked(libc.prctl(39, 0, 0, 0, 0))
    if nnp != 1:
        raise RuntimeError("no-new-privileges absent")
    denied_writes = {}
    for path in (action["source_path"], "/usr/local/bin/clang"):
        try:
            fd = os.open(path, os.O_WRONLY)
        except OSError as error:
            denied_writes[path] = error.errno
        else:
            os.close(fd)
            raise RuntimeError("immutable input/tool write succeeded")
    absent = {}
    for path in ("/src/zlib/zlib.h", "/proc/self/environ", "/dev/urandom", "/rgec-action.json"):
        try:
            os.stat(path)
        except OSError as error:
            absent[path] = error.errno
        else:
            raise RuntimeError("undeclared namespace entry visible: " + path)
    with open(action["source_path"], "rb") as stream:
        own_read = bool(stream.read(1))
    with open("/output/authority.json", "w") as stream:
        json.dump({"uid": os.geteuid(), "capabilities": caps, "bounding_capabilities": bounded,
                   "no_new_privs": nnp, "denied_write_errno": denied_writes,
                   "outside_fds_closed": True,
                   "undeclared_stat_errno": absent, "own_source_readable": own_read,
                   "complete_closure_certified": False, "live_clocks_closed": False}, stream)
    argv = ["/usr/local/bin/clang", "-x", action["language"]] + action["flags"]
    argv += ["-c", os.path.relpath(action["source_path"], action["cwd"]), "-o", "/output/action.o"]
    os.execve(argv[0], argv, {"PATH": "/usr/local/bin:/usr/bin:/bin", "TMPDIR": "/output",
                           "LANG": "C", "LC_ALL": "C"})
