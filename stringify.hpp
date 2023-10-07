#ifndef STRINGIFY_H
#define STRINGIFY_H 1

#include <eastl_compat.hpp>

#define MEM_IMAGE 0x1000000
#define MEM_MAPPED 0x40000
#define MEM_PRIVATE 0x20000

static inline eastl::string toString(uint64_t addr, size_t size, uint32_t type,
                                     uint32_t state, uint32_t protect) {
  eastl::string result = "0x";

  result += ::to_string_hex(addr, 16);
  result += " ";
  result += ::to_string(size);
  result += " ";

  switch (type) {
  case MEM_IMAGE:
    result += "MEM_IMAGE";
    break;
  case MEM_MAPPED:
    result += "MEM_MAPPED";
    break;
  case MEM_PRIVATE:
    result += "MEM_PRIVATE";
    break;
  default:
    result += "-";
    break;
  }
  result += " ";

  switch (state) {
  case MEM_COMMIT:
    result += "MEM_COMMIT";
    break;
  case MEM_FREE:
    result += "MEM_FREE";
    break;
  case MEM_RESERVE:
    result += "MEM_RESERVE";
    break;
  default:
    result += "-";
    break;
  }
  result += " ";

  if (protect & PAGE_READONLY) {
    result += "R";
  }
  if (protect & PAGE_READWRITE) {
    result += "RW";
  }
  if (protect & PAGE_EXECUTE_READWRITE) {
    result += "RWX";
  }
  if (protect & PAGE_EXECUTE) {
    result += "X";
  }
  if (protect & PAGE_WRITECOPY) {
    result += "C";
  }
  if (protect & PAGE_NOACCESS) {
    result += "NO_ACCESS";
  }

  return result;
}

#endif
