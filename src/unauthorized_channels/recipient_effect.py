"""Candidate recipient-owned Clang output residual (Python 3.5 compatible).

Run begin before shared lookup. The trusted caller must bind and freeze the
recipient directory for this operation. This is not an admission certificate:
timestamps, concurrent observations and full native diagnostics remain open.
"""

import binascii
import errno
import os
import stat


class EffectIneligible(Exception):
    """Run the entire action privately, without querying shared cache state."""


class RecipientOutput:
    def __init__(self, directory, name):
        if not name or name in ('.', '..') or '/' in name:
            raise ValueError('output must be one directory entry')
        self.name = name
        self.directory_fd = None
        self.output_fd = None
        self.temporary = None
        try:
            # O_PATH binds the directory without the observable IN_OPEN event
            # measured for an ordinary directory read fd on the native runtime.
            self.directory_fd = os.open(directory, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                current = os.stat(name, dir_fd=self.directory_fd)
            except OSError as error:
                if error.errno != errno.ENOENT:
                    raise
            else:
                if not stat.S_ISREG(current.st_mode) or not os.access(name, os.W_OK, dir_fd=self.directory_fd):
                    raise EffectIneligible('nonregular or unwritable destination')
            stem, extension = os.path.splitext(name)
            temporary = stem + '-' + binascii.hexlify(os.urandom(4)).decode() + extension + '.tmp'
            self.output_fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_CLOEXEC,
                                     0o666, dir_fd=self.directory_fd)
            self.temporary = temporary
        except (OSError, EffectIneligible) as error:
            self.close()
            raise EffectIneligible(str(error))

    def finish(self, object_bytes):
        """Success replaces the entry; compiler failure repeats native cleanup."""
        try:
            if object_bytes is not None:
                remaining = memoryview(object_bytes)
                while remaining:
                    written = os.write(self.output_fd, remaining)
                    remaining = remaining[written:]
                os.close(self.output_fd)
                self.output_fd = None
                os.rename(self.temporary, self.name, src_dir_fd=self.directory_fd,
                          dst_dir_fd=self.directory_fd)
                self.temporary = None
            else:
                os.close(self.output_fd)
                self.output_fd = None
                os.unlink(self.temporary, dir_fd=self.directory_fd)
                self.temporary = None
                # Clang's driver removes writable regular final outputs on a
                # failed job, even if its frontend only wrote a temporary file.
                try:
                    current = os.stat(self.name, dir_fd=self.directory_fd)
                except OSError as error:
                    if error.errno != errno.ENOENT:
                        raise
                else:
                    if stat.S_ISREG(current.st_mode) and os.access(self.name, os.W_OK, dir_fd=self.directory_fd):
                        os.unlink(self.name, dir_fd=self.directory_fd)
        finally:
            self.close()

    def close(self):
        if self.output_fd is not None:
            os.close(self.output_fd)
            self.output_fd = None
        if self.temporary is not None:
            os.unlink(self.temporary, dir_fd=self.directory_fd)
            self.temporary = None
        if self.directory_fd is not None:
            os.close(self.directory_fd)
            self.directory_fd = None
