/* Observe actual libc calls in real compiler processes; never replace results. */
#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static int trace_fd = -1;
static ssize_t (*next_write)(int, const void *, size_t);
static off_t (*next_lseek)(int, off_t, int);
static off64_t (*next_lseek64)(int, off64_t, int);
static ssize_t (*next_pwrite)(int, const void *, size_t, off_t);
static ssize_t (*next_pwrite64)(int, const void *, size_t, off64_t);
static int (*next_close)(int);

__attribute__((constructor)) static void initialize(void) {
  const char *value = getenv("RGEC_TRACE_FD");
  if (value) trace_fd = atoi(value);
  next_write = dlsym(RTLD_NEXT, "write");
  next_lseek = dlsym(RTLD_NEXT, "lseek");
  next_lseek64 = dlsym(RTLD_NEXT, "lseek64");
  next_pwrite = dlsym(RTLD_NEXT, "pwrite");
  next_pwrite64 = dlsym(RTLD_NEXT, "pwrite64");
  next_close = dlsym(RTLD_NEXT, "close");
  if (!next_write || !next_lseek || !next_lseek64 || !next_pwrite ||
      !next_pwrite64 || !next_close) _exit(111);
}

static void retain(const void *data, size_t size) {
  const char *cursor = data;
  while (size) {
    ssize_t count = syscall(SYS_write, trace_fd, cursor, size);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) _exit(112);
    cursor += count; size -= count;
  }
}

static void record(int kind, int fd, int64_t count, int64_t offset,
                   int64_t result, int error, const char *path, size_t path_size,
                   const void *data) {
  if (trace_fd < 0 || fd == trace_fd) return;
  int64_t header[] = {0x5247454354524331LL, kind, fd, count, offset,
                      result, error, (int64_t)path_size};
  retain(header, sizeof(header)); retain(path, path_size);
  if (data) retain(data, (size_t)count);
}

static size_t name(int fd, char *path) {
  char link[64];
  snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
  ssize_t size = readlink(link, path, 4096);
  return size < 0 ? 0 : (size_t)size;
}

ssize_t write(int fd, const void *data, size_t size) {
  int incoming = errno; char path[4096]; size_t length = name(fd, path);
  errno = incoming;
  ssize_t result = next_write(fd, data, size); int error = errno;
  record(0, fd, size, 0, result, result < 0 ? error : 0, path, length, data);
  errno = error; return result;
}

#define SEEK_WRAPPER(symbol, type, kind) \
type symbol(int fd, type offset, int whence) { \
  int incoming = errno; char path[4096]; size_t length = name(fd, path); \
  errno = incoming; type result = next_##symbol(fd, offset, whence); \
  int error = errno; \
  record(kind, fd, whence, offset, result, result < 0 ? error : 0, path, length, NULL); \
  errno = error; return result; \
}
SEEK_WRAPPER(lseek, off_t, 1)
SEEK_WRAPPER(lseek64, off64_t, 2)

#define PWRITE_WRAPPER(symbol, type, kind) \
ssize_t symbol(int fd, const void *data, size_t size, type offset) { \
  int incoming = errno; char path[4096]; size_t length = name(fd, path); \
  errno = incoming; ssize_t result = next_##symbol(fd, data, size, offset); \
  int error = errno; \
  record(kind, fd, size, offset, result, result < 0 ? error : 0, path, length, data); \
  errno = error; return result; \
}
PWRITE_WRAPPER(pwrite, off_t, 3)
PWRITE_WRAPPER(pwrite64, off64_t, 4)

int close(int fd) {
  int incoming = errno; char path[4096]; size_t length = name(fd, path);
  errno = incoming; int result = next_close(fd); int error = errno;
  record(5, fd, 0, 0, result, result < 0 ? error : 0, path, length, NULL);
  errno = error; return result;
}
