// Capture genuine native entry memory; no cached or substituted analysis.
#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/CodeGen/SelectionDAGNodes.h"
#include "llvm/Support/KnownBits.h"
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cerrno>
#include <fcntl.h>
#include <asm/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

using namespace llvm;
#define KNOWN_SYMBOL "_ZNK4llvm12SelectionDAG16computeKnownBitsENS_7SDValueERNS_9KnownBitsERKNS_5APIntEj"
extern "C" void native_known(const SelectionDAG *, SDValue, KnownBits *, const APInt *, unsigned) asm("__real_" KNOWN_SYMBOL);
extern "C" void captured_known(const SelectionDAG *, SDValue, KnownBits *, const APInt *, unsigned) asm("__wrap_" KNOWN_SYMBOL);

namespace {
uint64_t counters[12] = {};
bool initialized, captured;

void finish() {
  const char *path = std::getenv("RGEC_KNOWNBITS_METRICS");
  if (!path) return;
  FILE *f = std::fopen(path, "wb");
  if (!f || std::fwrite(counters, sizeof(counters), 1, f) != 1 || std::fclose(f)) _exit(124);
}

// /proc/self/mem reads the actual process. Each retained segment is a readable,
// writable mapping, including real heap/caller storage and initialized globals.
// Immutable executable data comes from the pinned ELF in the checker. Omitted
// mappings are unsupported reads, never zero-filled substitutes.
void snapshot(const char *path, const SelectionDAG *dag, SDValue op,
              KnownBits *known, const APInt *demanded, unsigned depth) {
  int savedErrno = errno;
  char mapsPath[4096], dataPath[4096];
  if (std::snprintf(mapsPath, sizeof(mapsPath), "%s.maps", path) >= int(sizeof(mapsPath)) ||
      std::snprintf(dataPath, sizeof(dataPath), "%s.memory", path) >= int(sizeof(dataPath))) _exit(124);
  FILE *maps = std::fopen("/proc/self/maps", "r"), *index = std::fopen(mapsPath, "wb");
  FILE *data = std::fopen(dataPath, "wb"), *meta = std::fopen(path, "wb");
  int input = ::open("/proc/self/mem", O_RDONLY);
  if (!maps || !index || !data || !meta || input < 0) _exit(124);
  unsigned long fsBase, gsBase;
  if (::syscall(SYS_arch_prctl, ARCH_GET_FS, &fsBase)) { std::perror("native capture ARCH_GET_FS"); _exit(124); }
  long gsStatus = ::syscall(SYS_arch_prctl, ARCH_GET_GS, &gsBase);
  int gsErrno = gsStatus ? errno : 0;
  std::fprintf(meta, "{\"args\":[%llu,%llu,%u,%llu,%llu,%u],\"opcode\":%u,\"child_opcode\":%u,\"width\":%u,\"known_before_hex\":\"",
    (unsigned long long)dag, (unsigned long long)op.getNode(), op.getResNo(),
    (unsigned long long)known, (unsigned long long)demanded, depth,
    op.getOpcode(), op.getOperand(0).getOpcode(), op.getScalarValueSizeInBits());
  const unsigned char *before = reinterpret_cast<const unsigned char *>(known);
  for (unsigned i = 0; i < sizeof(KnownBits); ++i) std::fprintf(meta, "%02x", before[i]);
  std::fprintf(meta, "\",\"known_size\":%zu,\"fs_base\":%lu,\"gs_base\":", sizeof(KnownBits), fsBase);
  if (gsStatus) std::fputs("null", meta); else std::fprintf(meta, "%lu", gsBase);
  std::fprintf(meta, ",\"gs_capture_status\":%ld,\"gs_capture_errno\":%d}\n", gsStatus, gsErrno);
  if (std::fclose(meta)) _exit(124);
  errno = savedErrno;
  char line[8192], permissions[5], buffer[65536];
  unsigned long long start, stop, offset = 0;
  while (std::fgets(line, sizeof(line), maps)) {
    if (std::sscanf(line, "%llx-%llx %4s", &start, &stop, permissions) != 3) _exit(124);
    if (permissions[0] != 'r' || permissions[1] != 'w' || permissions[2] == 'x') continue;
    std::fprintf(index, "%llx %llx %llu %s\n", start, stop, offset, permissions);
    for (unsigned long long address = start; address < stop;) {
      size_t size = (stop - address < sizeof(buffer)) ? stop - address : sizeof(buffer);
      ssize_t got = ::pread(input, buffer, size, address);
      if (got != ssize_t(size) || std::fwrite(buffer, 1, size, data) != size) _exit(124);
      address += size; offset += size;
    }
  }
  if (std::ferror(maps) || std::fclose(maps) || std::fclose(index) || std::fclose(data) || ::close(input)) _exit(124);
  errno = savedErrno;
}
} // namespace

extern "C" void captured_known(const SelectionDAG *dag, SDValue op, KnownBits *known,
                                const APInt *demanded, unsigned depth) {
  if (!initialized) { initialized = true; std::atexit(finish); }
  ++counters[0];
  const char *path = std::getenv("RGEC_NATIVE_CAPTURE");
#ifdef RGEC_ARITHMETIC_CAPTURE
  bool take = path && !captured && depth == 0 && op.getOpcode() == ISD::ADD &&
    op.getNumOperands() == 2 && op.getOperand(0).getOpcode() == ISD::SRL &&
    op.getOperand(1).getOpcode() == ISD::Constant &&
    op.getScalarValueSizeInBits() == 64 && demanded->getBitWidth() == 1 &&
    demanded->getZExtValue() == 1 && known->getBitWidth() <= 64;
#else
  bool take = path && !captured && depth == 0 && op.getOpcode() == ISD::TRUNCATE &&
    op.getScalarValueSizeInBits() == 32 && demanded->getBitWidth() == 1 &&
    demanded->getZExtValue() == 1 && known->getBitWidth() <= 64;
#endif
  if (take) { captured = true; ++counters[1]; snapshot(path, dag, op, known, demanded, depth); }
  else ++counters[4];
  native_known(dag, op, known, demanded, depth);
  if (take) {
    int nativeErrno = errno;
    char afterPath[4096];
    if (std::snprintf(afterPath, sizeof(afterPath), "%s.after", path) >= int(sizeof(afterPath))) _exit(124);
    FILE *f = std::fopen(afterPath, "wb");
    if (!f || std::fwrite(known, sizeof(KnownBits), 1, f) != 1 || std::fclose(f)) _exit(124);
    errno = nativeErrno;
  }
}
