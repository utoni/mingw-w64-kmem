#ifndef STRINGIFY_H
#define STRINGIFY_H 1

#include <eastl_compat.hpp>

#define MEM_IMAGE 0x1000000
#define MEM_MAPPED 0x40000
#define MEM_PRIVATE 0x20000

#define MEM_RESET_UNDO 0x1000000
#define MEM_PHYSICAL 0x00400000
#define MEM_WRITE_WATCH 0x00200000

#define PAGE_TARGETS_INVALID 0x40000000

static inline eastl::string toString(uint64_t addr, size_t size, uint32_t type,
                                     uint32_t state, uint32_t protect) {
  eastl::string result = "0x";

  result += ::to_string_hex(addr, 16);
  result += " ";
  result += ::to_string(size);
  result += " ";

  if (type & MEM_IMAGE) {
    result += "MEM_IMAGE,";
  }
  if (type & MEM_MAPPED) {
    result += "MEM_MAPPED,";
  }
  if (type & MEM_PRIVATE) {
    result += "MEM_PRIVATE,";
  }
  if ((type & ~(MEM_IMAGE | MEM_MAPPED | MEM_PRIVATE)) != 0) {
    result += "...,";
  }
  result.pop_back();
  result += " ";

  if (state & MEM_COMMIT) {
    result += "MEM_COMMIT,";
  }
  if (state & MEM_FREE) {
    result += "MEM_FREE,";
  }
  if (state & MEM_RESERVE) {
    result += "MEM_RESERVE,";
  }
  if (state & MEM_RESET_UNDO) {
    result += "MEM_RESET_UNDO,";
  }
  if (state & MEM_RESET) {
    result += "MEM_RESET,";
  }
  if (state & MEM_LARGE_PAGES) {
    result += "MEM_LARGE_PAGES,";
  }
  if (state & MEM_PHYSICAL) {
    result += "MEM_PHYSICAL,";
  }
  if (state & MEM_TOP_DOWN) {
    result += "MEM_TOP_DOWN,";
  }
  if (state & MEM_WRITE_WATCH) {
    result += "MEM_WRITE_WATCH,";
  }
  result.pop_back();
  result += " ";

  if (protect & PAGE_READONLY) {
    result += "R,";
  }
  if (protect & PAGE_READWRITE) {
    result += "RW,";
  }
  if (protect & PAGE_EXECUTE_READ) {
    result += "RX,";
  }
  if (protect & PAGE_EXECUTE_READWRITE) {
    result += "RWX,";
  }
  if (protect & PAGE_EXECUTE) {
    result += "X,";
  }
  if (protect & PAGE_EXECUTE_WRITECOPY) {
    result += "RWXC,";
  }
  if (protect & PAGE_WRITECOPY) {
    result += "C,";
  }
  if (protect & PAGE_NOACCESS) {
    result += "NO_ACCESS,";
  }
  if (protect & PAGE_TARGETS_INVALID) {
    result += "CFG_INVALID,";
  }
  if (protect & PAGE_GUARD) {
    result += "PAGE_GUARD,";
  }
  if (protect & PAGE_NOCACHE) {
    result += "PAGE_NOCACHE,";
  }
  if (protect & PAGE_WRITECOMBINE) {
    result += "PAGE_WRITECOMBINE,";
  }
  if ((protect &
       ~(PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE | PAGE_EXECUTE_WRITECOPY |
         PAGE_WRITECOPY | PAGE_NOACCESS | PAGE_TARGETS_INVALID | PAGE_GUARD |
         PAGE_NOCACHE | PAGE_WRITECOMBINE)) != 0) {
    result += "...,";
  }
  result.pop_back();

  return result;
}

#endif
