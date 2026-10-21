"""Trusted launcher for the pinned image's Python 3.5 and x86-64 Linux ABI.

Not an agent tool. Landlock limits content opens and writes; metadata and time
are deliberately reported as unresolved rather than treated as closed inputs.
"""

import ctypes
import json
import os
import platform


class Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def check(result):
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def confine(source):
    if platform.machine() != "x86_64":
        raise RuntimeError("unsupported syscall architecture")
    libc = ctypes.CDLL(None, use_errno=True)
    abi = check(libc.syscall(444, 0, 0, 1))
    if abi < 3:
        raise RuntimeError("Landlock ABI 3 required; no unrestricted fallback")
    handled = (1 << 15) - 1
    ruleset = Ruleset(handled)
    fd = check(libc.syscall(444, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0))
    read = (1 << 0) | (1 << 2) | (1 << 3)
    output = handled & ~((1 << 0) | (1 << 6) | (1 << 9) | (1 << 11))
    paths = [(p, read) for p in ("/usr", "/bin", "/lib", "/lib64")]
    paths += [(source, 1 << 2), ("/etc/ld.so.cache", 1 << 2),
              ("/dev/null", (1 << 1) | (1 << 2)), ("/output", output)]
    try:
        for path, rights in paths:
            parent = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = PathRule(rights, parent)
                check(libc.syscall(445, fd, 1, ctypes.byref(rule), 0))
            finally:
                os.close(parent)
        check(libc.prctl(38, 1, 0, 0, 0))
        check(libc.syscall(446, fd, 0))
    finally:
        os.close(fd)
    return abi


if __name__ == "__main__":
    with open("/rgec-action.json") as stream:
        action = json.load(stream)
    status = dict(line.strip().split(":", 1) for line in open("/proc/self/status") if ":" in line)
    os.chdir(action["cwd"])
    abi = confine(action["source_path"])
    source_write_denied = False
    try:
        descriptor = os.open(action["source_path"], os.O_WRONLY)
    except OSError:
        source_write_denied = True
    else:
        os.close(descriptor)
    denied_reads = {}
    for path in ("/src/zlib/zlib.h", "/proc/self/environ", "/dev/urandom", "/rgec-action.json"):
        try:
            descriptor = os.open(path, os.O_RDONLY)
        except OSError as error:
            denied_reads[path] = error.errno
        else:
            os.close(descriptor)
            raise RuntimeError("undeclared content read succeeded: " + path)
    # Preserve this limitation as an observed counterexample to complete closure.
    metadata_visible = os.stat("/src/zlib/zlib.h").st_size
    with open("/output/authority.json", "w") as stream:
        json.dump({
            "landlock_abi": abi, "source_write_denied": source_write_denied,
            "denied_read_errno": denied_reads, "undeclared_metadata_visible": metadata_visible,
            "capabilities": {k: status[k].strip() for k in ("CapEff", "CapPrm", "CapBnd")},
            "no_new_privs": int(status["NoNewPrivs"]),
            "complete_closure_certified": False,
        }, stream, sort_keys=True)
    argv = ["/usr/local/bin/clang", "-x", action["language"]] + action["flags"]
    argv += ["-c", os.path.relpath(action["source_path"], action["cwd"]), "-o", "/output/action.o"]
    os.execve(argv[0], argv, {"PATH": "/usr/local/bin:/usr/bin:/bin", "TMPDIR": "/output",
                           "LANG": "C", "LC_ALL": "C"})
