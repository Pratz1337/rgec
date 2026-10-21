// Experimental source-derived scalar scope. Native equivalence is not certified.
#include "llvm/CodeGen/SelectionDAG.h"
#include "llvm/CodeGen/SelectionDAGNodes.h"
#include "llvm/Support/KnownBits.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

using namespace llvm;

#define KNOWN_SYMBOL "_ZNK4llvm12SelectionDAG16computeKnownBitsENS_7SDValueERNS_9KnownBitsERKNS_5APIntEj"
extern "C" void native_known(const SelectionDAG *, SDValue, KnownBits *, const APInt *, unsigned) asm("__real_" KNOWN_SYMBOL);
extern "C" void scoped_known(const SelectionDAG *, SDValue, KnownBits *, const APInt *, unsigned) asm("__wrap_" KNOWN_SYMBOL);

namespace {
constexpr unsigned Words = 512, Capacity = 512;
struct Key {
  uint64_t data[Words]; unsigned size = 0;
  bool add(uint64_t x) { if (size == Words) return false; data[size++] = x; return true; }
};
struct Bits { uint64_t zero, one; unsigned width; };
struct Entry { Key key; Bits bits; uint64_t hash = 0; bool occupied = false; };
Entry store[Capacity];
uint64_t counters[12] = {}; // calls, admitted, hits, misses, rejected, checks,
                         // native disagreements, key conflicts, stores,
                         // replacements, imported entries, direct evaluations.
const char *mode;
bool initialized;

uint64_t mask(unsigned width) { return UINT64_MAX >> (64 - width); }

// This projection is constructed before store access. No node address is used
// by the accepted source branches; rejected operations execute native code.
bool project(SDValue op, unsigned depth, Key &key) {
  EVT vt = op.getValueType();
  if (!vt.isSimple() || vt.isVector() || !vt.isInteger()) return false;
  unsigned width = vt.getSizeInBits(), opcode = op.getOpcode();
  if (!width || width > 64 || depth > 6) return false;
  if (!key.add(opcode) || !key.add(width) || !key.add(op.getResNo()) || !key.add(depth)) return false;
  if (opcode == ISD::Constant || opcode == ISD::TargetConstant) {
    const APInt &value = cast<ConstantSDNode>(op)->getAPIntValue();
    return value.getBitWidth() == width && key.add(value.getZExtValue());
  }
  if (depth == 6) return true;
  if (opcode == ISD::LOAD) {
    const LoadSDNode *load = cast<LoadSDNode>(op);
    unsigned extension = load->getExtensionType();
    if (extension == ISD::ZEXTLOAD && op.getResNo() == 0) {
      EVT memory = load->getMemoryVT();
      if (!memory.isSimple() || memory.isVector() || !memory.isInteger()) return false;
      unsigned memoryWidth = memory.getSizeInBits();
      return memoryWidth && memoryWidth <= width && key.add(extension) && key.add(memoryWidth);
    }
    // The metadata helper is not in this domain, even if its current result is zero.
    if (load->getRanges()) return false;
    return key.add(extension) && key.add(0);
  }
  unsigned operands;
  switch (opcode) {
  case ISD::AND: case ISD::OR: case ISD::XOR: operands = 2; break;
  case ISD::ZERO_EXTEND: case ISD::SIGN_EXTEND: case ISD::ANY_EXTEND:
  case ISD::TRUNCATE: operands = 1; break;
  default: return false;
  }
  if (op.getNumOperands() != operands) return false;
  for (unsigned i = 0; i < operands; ++i) {
    EVT child = op.getOperand(i).getValueType();
    if (!child.isSimple() || child.isVector() || !child.isInteger()) return false;
    unsigned childWidth = child.getSizeInBits();
    if (operands == 2 && childWidth != width) return false;
    if (opcode == ISD::TRUNCATE ? childWidth <= width : operands == 1 && childWidth >= width) return false;
    if (!project(op.getOperand(i), depth + 1, key)) return false;
  }
  return true;
}

// Capable direct baseline: compute from the same checked scalar projection.
Bits evaluate(const Key &key, unsigned &cursor) {
  unsigned opcode = key.data[cursor++], width = key.data[cursor++];
  unsigned result = key.data[cursor++], depth = key.data[cursor++];
  Bits bits{0, 0, width}; uint64_t all = mask(width);
  if (opcode == ISD::Constant || opcode == ISD::TargetConstant) {
    bits.one = key.data[cursor++]; bits.zero = ~bits.one & all; return bits;
  }
  if (depth == 6) return bits;
  if (opcode == ISD::LOAD) {
    unsigned extension = key.data[cursor++], memoryWidth = key.data[cursor++];
    if (extension == ISD::ZEXTLOAD && result == 0) bits.zero = all & ~mask(memoryWidth);
    return bits;
  }
  Bits left = evaluate(key, cursor);
  if (opcode == ISD::AND || opcode == ISD::OR || opcode == ISD::XOR) {
    Bits right = evaluate(key, cursor);
    if (opcode == ISD::AND) { bits.zero = left.zero | right.zero; bits.one = left.one & right.one; }
    if (opcode == ISD::OR) { bits.zero = left.zero & right.zero; bits.one = left.one | right.one; }
    if (opcode == ISD::XOR) {
      bits.zero = (left.zero & right.zero) | (left.one & right.one);
      bits.one = (left.zero & right.one) | (left.one & right.zero);
    }
  } else {
    bits.zero = left.zero & all; bits.one = left.one & all;
    uint64_t high = all & ~mask(left.width);
    if (opcode == ISD::ZERO_EXTEND) bits.zero |= high;
    if (opcode == ISD::SIGN_EXTEND) {
      if (left.zero & (uint64_t(1) << (left.width - 1))) bits.zero |= high;
      if (left.one & (uint64_t(1) << (left.width - 1))) bits.one |= high;
    }
  }
  return bits;
}

uint64_t hash(const Key &key) {
  uint64_t h = 1469598103934665603ULL;
  for (unsigned i = 0; i < key.size; ++i) { h ^= key.data[i]; h *= 1099511628211ULL; }
  return h;
}
bool same(const Key &a, const Key &b) {
  return a.size == b.size && std::memcmp(a.data, b.data, a.size * sizeof(uint64_t)) == 0;
}
bool same(Bits a, Bits b) { return a.width == b.width && a.zero == b.zero && a.one == b.one; }
Bits snapshot(const KnownBits &known) {
  return {known.Zero.getZExtValue(), known.One.getZExtValue(), known.getBitWidth()};
}
void assign(KnownBits &known, Bits bits) {
  known.Zero = APInt(bits.width, bits.zero); known.One = APInt(bits.width, bits.one);
}

void finish() {
  if (const char *path = std::getenv("RGEC_KNOWNBITS_METRICS")) {
    FILE *f = std::fopen(path, "wb");
    if (!f || std::fwrite(counters, sizeof(counters), 1, f) != 1 || std::fclose(f)) _exit(124);
  }
  if (const char *path = std::getenv("RGEC_KNOWNBITS_EXPORT")) {
    FILE *f = std::fopen(path, "wb");
    if (!f) _exit(124);
    for (const Entry &entry : store) if (entry.occupied) {
      uint64_t header[4] = {entry.key.size, entry.bits.width, entry.bits.zero, entry.bits.one};
      if (std::fwrite(header, sizeof(header), 1, f) != 1 ||
          std::fwrite(entry.key.data, sizeof(uint64_t), entry.key.size, f) != entry.key.size) _exit(124);
    }
    if (std::fclose(f)) _exit(124);
  }
}
void initialize() {
  mode = std::getenv("RGEC_KNOWNBITS_MODE"); if (!mode) mode = "native";
  initialized = true; std::atexit(finish);
  // Host-owned experimental packets from the very same native binary. This
  // transport is not an untrusted store or a proof of the native transition.
  if (const char *path = std::getenv("RGEC_KNOWNBITS_IMPORT")) {
    FILE *f = std::fopen(path, "rb"); if (!f) _exit(124);
    uint64_t header[4];
    while (std::fread(header, sizeof(header), 1, f) == 1) {
      Key key; key.size = header[0];
      if (!key.size || key.size > Words || !header[1] || header[1] > 64 ||
          std::fread(key.data, sizeof(uint64_t), key.size, f) != key.size) _exit(124);
      uint64_t h = hash(key); Entry &entry = store[h % Capacity];
      entry.key.size = key.size; std::memcpy(entry.key.data, key.data, key.size * sizeof(uint64_t));
      entry.hash = h; entry.bits = {header[2], header[3], unsigned(header[1])};
      entry.occupied = true; ++counters[10];
    }
    if (!std::feof(f) || std::fclose(f)) _exit(124);
  }
}
} // namespace

extern "C" void scoped_known(const SelectionDAG *dag, SDValue op, KnownBits *known,
                             const APInt *demanded, unsigned depth) {
  if (!initialized) initialize();
  ++counters[0];
  if (!std::strcmp(mode, "native")) { native_known(dag, op, known, demanded, depth); return; }
  Key key;
  if (demanded->getBitWidth() != 1 || demanded->getZExtValue() != 1 || !project(op, depth, key)) {
    ++counters[4]; native_known(dag, op, known, demanded, depth); return;
  }
  ++counters[1];
  if (!std::strcmp(mode, "guard")) { native_known(dag, op, known, demanded, depth); return; }
  unsigned cursor = 0;
  if (!std::strcmp(mode, "direct")) {
    assign(*known, evaluate(key, cursor)); if (cursor != key.size) _exit(125);
    ++counters[11]; return;
  }
  uint64_t h = hash(key); Entry &entry = store[h % Capacity];
  bool hit = entry.occupied && entry.hash == h && same(entry.key, key);
  ++counters[hit ? 2 : 3];
  if (!std::strcmp(mode, "cache") && hit) { assign(*known, entry.bits); return; }
  native_known(dag, op, known, demanded, depth);
  Bits actual = snapshot(*known);
  if (!std::strcmp(mode, "shadow")) {
    Bits predicted = evaluate(key, cursor); ++counters[5];
    if (cursor != key.size || !same(actual, predicted)) { ++counters[6]; _exit(125); }
  }
  if (hit && !same(actual, entry.bits)) { ++counters[7]; _exit(125); }
  if (!hit) {
    if (entry.occupied) ++counters[9];
    entry.key.size = key.size; std::memcpy(entry.key.data, key.data, key.size * sizeof(uint64_t));
    entry.bits = actual; entry.hash = h; entry.occupied = true; ++counters[8];
  }
}
