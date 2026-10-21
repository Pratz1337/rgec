// Observe actual native analysis costs and answers; never replace computation.
#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/CodeGen/SelectionDAGNodes.h"
#include "llvm/Support/KnownBits.h"
#include <cpuid.h>
#include <x86intrin.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>

using namespace llvm;
#define KNOWN_SYMBOL "_ZNK4llvm12SelectionDAG16computeKnownBitsENS_7SDValueERNS_9KnownBitsERKNS_5APIntEj"
extern "C" void native_known(const SelectionDAG *, SDValue, KnownBits *, const APInt *, unsigned) asm("__real_" KNOWN_SYMBOL);
extern "C" void observed_known(const SelectionDAG *, SDValue, KnownBits *, const APInt *, unsigned) asm("__wrap_" KNOWN_SYMBOL);

namespace {
FILE *output;
bool initialized;
uint64_t counters[12] = {};

uint64_t stamp(unsigned &aux) {
  _mm_lfence(); uint64_t value = __rdtscp(&aux); _mm_lfence(); return value;
}
void write(const uint64_t (&words)[20]) {
  if (std::fwrite(words, sizeof(words), 1, output) != 1) _exit(124);
}
void finish() {
  if (output && std::fclose(output)) _exit(124);
  if (const char *path = std::getenv("RGEC_KNOWNBITS_METRICS")) {
    FILE *f = std::fopen(path, "wb");
    if (!f || std::fwrite(counters, sizeof(counters), 1, f) != 1 || std::fclose(f)) _exit(124);
  }
}
void initialize() {
  initialized = true; std::atexit(finish);
  const char *path = std::getenv("RGEC_KNOWNBITS_CENSUS");
  if (!path) return;
  unsigned a, b, c, d;
  if (!__get_cpuid(0x80000001, &a, &b, &c, &d) || !(d & (1u << 27))) _exit(124);
  output = std::fopen(path, "wb"); if (!output) _exit(124);
  for (unsigned i = 0; i < 64; ++i) {
    unsigned first, last; uint64_t start = stamp(first), stop = stamp(last);
    uint64_t words[20] = {0x524745434b435331, 0, i, 0, 0, 0, 0, 0, 0, 0,
                         0, 0, 0, 0, 0, stop - start, first, last, 0, 0};
    write(words);
  }
}
} // namespace

extern "C" void observed_known(const SelectionDAG *dag, SDValue op, KnownBits *known,
                                const APInt *demanded, unsigned depth) {
  int savedErrno = errno;
  if (!initialized) initialize();
  ++counters[0];
  if (!output) { errno = savedErrno; native_known(dag, op, known, demanded, depth); return; }
  unsigned count = op.getNumOperands();
  uint64_t words[20] = {0x524745434b435331, 1, counters[0], op.getOpcode(),
    op.getScalarValueSizeInBits(), op.getResNo(), depth, demanded->getBitWidth(),
    demanded->getBitWidth() <= 64 ? demanded->getZExtValue() : 0, known->getBitWidth(),
    0, 0, count ? op.getOperand(0).getOpcode() : UINT64_MAX,
    count > 1 ? op.getOperand(1).getOpcode() : UINT64_MAX, count, 0, 0, 0, 0,
    op.getValueType().isVector()};
  unsigned first, last;
  errno = savedErrno;
  uint64_t start = stamp(first);
  native_known(dag, op, known, demanded, depth);
  uint64_t stop = stamp(last);
  int nativeErrno = errno;
  words[15] = stop - start; words[16] = first; words[17] = last;
  words[18] = known->getBitWidth();
  if (known->getBitWidth() <= 64) {
    words[10] = known->Zero.getZExtValue(); words[11] = known->One.getZExtValue(); ++counters[1];
  } else ++counters[4];
  write(words); errno = nativeErrno;
}
