// Observe authentic matcher calls; all native computation still executes.
#include "llvm/CodeGen/SelectionDAGISel.h"
#include "llvm/CodeGen/SelectionDAGNodes.h"
#include <cstdint>
#include <cstdlib>
#include <unistd.h>

using namespace llvm;

static void report(const uint64_t (&words)[10]) {
  const char *value = std::getenv("RGEC_MATCHER_CENSUS_FD");
  if (!value) return;
  // A private regular file, retained by the host; never a compiler stream.
  if (::write(std::atoi(value), words, sizeof(words)) != sizeof(words))
    _exit(123);
}

#define SELECT_SYMBOL "_ZN4llvm16SelectionDAGISel16SelectCodeCommonEPNS_6SDNodeEPKhj"
#define AND_SYMBOL "_ZNK4llvm16SelectionDAGISel12CheckAndMaskENS_7SDValueEPNS_14ConstantSDNodeEl"
#define OR_SYMBOL "_ZNK4llvm16SelectionDAGISel11CheckOrMaskENS_7SDValueEPNS_14ConstantSDNodeEl"

extern "C" void native_select(SelectionDAGISel *, SDNode *, const unsigned char *, unsigned) asm("__real_" SELECT_SYMBOL);
extern "C" void observed_select(SelectionDAGISel *, SDNode *, const unsigned char *, unsigned) asm("__wrap_" SELECT_SYMBOL);
extern "C" bool native_and(const SelectionDAGISel *, SDValue, ConstantSDNode *, int64_t) asm("__real_" AND_SYMBOL);
extern "C" bool observed_and(const SelectionDAGISel *, SDValue, ConstantSDNode *, int64_t) asm("__wrap_" AND_SYMBOL);
extern "C" bool native_or(const SelectionDAGISel *, SDValue, ConstantSDNode *, int64_t) asm("__real_" OR_SYMBOL);
extern "C" bool observed_or(const SelectionDAGISel *, SDValue, ConstantSDNode *, int64_t) asm("__wrap_" OR_SYMBOL);

extern "C" void observed_select(SelectionDAGISel *selector, SDNode *node,
                               const unsigned char *table, unsigned size) {
  uint64_t words[10] = {0x524745434d435331, 0, node->getOpcode(),
    node->getNumOperands(), node->getNumValues(), size, table[0], 0, 0, 0};
  report(words);
  native_select(selector, node, table, size);
}

static bool mask(unsigned kind, const SelectionDAGISel *selector, SDValue lhs,
                 ConstantSDNode *rhs, int64_t desired,
                 bool (*native)(const SelectionDAGISel *, SDValue, ConstantSDNode *, int64_t)) {
  const APInt &actual = rhs->getAPIntValue();
  unsigned width = lhs.getValueSizeInBits();
  unsigned opcode = lhs.getOpcode(), actualWidth = actual.getBitWidth();
  unsigned path = 3;
  uint64_t value = 0, wanted = 0;
  if (width && width <= 64 && actualWidth == width) {
    value = actual.getZExtValue();
    wanted = static_cast<uint64_t>(desired) & (UINT64_MAX >> (64 - width));
    path = value == wanted ? 0 : (value & ~wanted) ? 1 : 2;
  }
  bool result = native(selector, lhs, rhs, desired);
  uint64_t words[10] = {0x524745434d435331, kind, opcode, width,
    actualWidth, value, wanted, path, result, static_cast<uint64_t>(desired)};
  report(words);
  return result;
}

extern "C" bool observed_and(const SelectionDAGISel *selector, SDValue lhs,
                             ConstantSDNode *rhs, int64_t desired) {
  return mask(1, selector, lhs, rhs, desired, native_and);
}

extern "C" bool observed_or(const SelectionDAGISel *selector, SDValue lhs,
                            ConstantSDNode *rhs, int64_t desired) {
  return mask(2, selector, lhs, rhs, desired, native_or);
}
