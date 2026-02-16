#include <cstdint>
#include <EASTL/finally.h>
#include <EASTL/string.h>
#include <except.h>
#include <stdint.h>

#include "ipc.hpp"
#include "memory.hpp"

using namespace IPC;

static constexpr std::initializer_list<std::uint8_t> magic = { 0xDE, 0xAD, 0xC0, 0xDE, 0xCA, 0xFE, 0xCA, 0xFE };
static constexpr eastl::string_view magic_mask = "xxxxxxxx";
static constexpr std::size_t magic_size = magic.size();

extern "C" {
  struct rcu_slot {
    volatile long long int generation;
    unsigned char data[0];
  };

  struct rcu_shared {
    uint8_t magic[magic_size];
    volatile long long int active;
    struct rcu_slot* slots_memory[0];
  };

#ifdef BUILD_USERMODE
  extern void* VirtualAlloc(void* lpAddress, size_t dwSize, unsigned int flAllocationType,
                            unsigned int flProtect);
#endif
}

#ifdef BUILD_USERMODE
UserSharedMemory::UserSharedMemory() : m_shm_size{0}, m_slots{0}, m_memory{nullptr} {
}

UserSharedMemory::~UserSharedMemory() {
  // DO NOT `VirtualFree()` m_memory!
}

bool UserSharedMemory::Allocate(std::size_t shm_size, std::size_t slots) {
  if (m_memory)
    return false;

  m_memory = ::VirtualAlloc(nullptr, sizeof(rcu_shared) + sizeof(void*) * slots,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!m_memory)
    return false;

  auto rcu_shared = reinterpret_cast<struct rcu_shared*>(m_memory);
  ::memcpy(rcu_shared->magic, magic.begin(), magic_size);
  m_shm_size = shm_size;
  m_slots = slots;
  rcu_shared->active = 0;

  for (auto i = 0; i < slots; ++i) {
    rcu_shared->slots_memory[i] = reinterpret_cast<struct rcu_slot*>(VirtualAlloc(nullptr, sizeof(rcu_slot) + shm_size,
                                                                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  }
  for (auto i = 0; i < slots; ++i) {
    if (!rcu_shared->slots_memory[i])
      return false;
  }

  return true;
}

void* UserSharedMemory::GetSlotData(std::size_t slot) {
  if (slot >= m_slots)
    return nullptr;

  auto rcu_shared = reinterpret_cast<struct rcu_shared*>(m_memory);
  auto rcu_slot = &rcu_shared->slots_memory[slot]->data[0];
  return rcu_slot;
}

#else // BUILD_USERMODE

extern "C" {
int map_exception_handler(_In_ EXCEPTION_POINTERS *lpEP) {
  (void)lpEP;
  return EXCEPTION_EXECUTE_HANDLER;
}
}

KernelSharedMemory::Chunk::~Chunk() {
}

bool KernelSharedMemory::Chunk::MapToSystem(_In_ PEPROCESS pep, _In_ _Out_ PMDL* mdl) {
  PVOID kernel_va;
  KAPC_STATE apc;

  if (Type != IS_INVALID)
    return false;

  *mdl = IoAllocateMdl(
    reinterpret_cast<void*>(UserVA), UserSize,
    FALSE, FALSE, NULL
  );
  if (!*mdl)
    return false;

  KeStackAttachProcess((PKPROCESS)pep, &apc);

  bool failed = false;
  __dpptry(map_exception_handler, map_seh) {
    MmProbeAndLockPages(
      *mdl,
      UserMode,
      IoWriteAccess
    );
  }
  __dppexcept(map_seh) { failed = true; }
  __dpptryend(map_seh);

  KeUnstackDetachProcess(&apc);
  if (failed) {
    IoFreeMdl(*mdl);
    *mdl = nullptr;
    return false;
  }

  kernel_va = MmGetSystemAddressForMdlSafe(*mdl, NormalPagePriority);
  if (!kernel_va) {
    if ((*mdl)->MdlFlags & MDL_PAGES_LOCKED)
      MmUnlockPages(*mdl);
    IoFreeMdl(*mdl);
    *mdl = nullptr;
    return false;
  }

  Memory = kernel_va;
  Type = IS_MAPPED;
  return true;
}

bool KernelSharedMemory::Chunk::UnmapFromSystem(_In_ _Out_ PMDL* mdl) {
  if (Type != IS_MAPPED)
    return false;
  if ((*mdl)->MdlFlags & MDL_PAGES_LOCKED)
    MmUnlockPages(*mdl);
  IoFreeMdl(*mdl);
  Memory = nullptr;
  Type = IS_INVALID;
  *mdl = nullptr;
  return true;
}

bool KernelSharedMemory::Chunk::CopyToSystem(_In_ PEPROCESS pep) {
  return false;
}

bool KernelSharedMemory::Chunk::CopyFromSystem(_In_ PEPROCESS pep) {
  return false;
}

KernelSharedMemory::KernelSharedMemory()
  : m_shm_size{0}, m_slots{0}, m_chunks{} {
}

KernelSharedMemory::~KernelSharedMemory() {
}

bool KernelSharedMemory::FindSharedMemory(std::size_t shm_size, std::size_t slots,
                                          const Process& target_proc) {
  m_pid = reinterpret_cast<HANDLE>(target_proc.UniqueProcessId);
  PEPROCESS pep;
  HANDLE obj;

  if (!NT_SUCCESS(::OpenProcess(m_pid, &pep, &obj)))
    return false;
  eastl::finally close_process_on_return([&pep, &obj]() {
    ::CloseProcess(&pep, &obj);
    pep = nullptr;
    obj = nullptr;
  });

  PatternScanner::Page scanner(pep, obj, magic, magic_mask);
  PatternScanner::ResultVec results;
  auto found = scanner.Scan([](const Page & page) {
    return page.BaseAddress < 0x00007FF000000000 && (page.Type & MEM_PRIVATE) != 0;
  }, results, 2);
  if (!found)
    return false;
  if (results.size() != 1)
    return false;

  PMDL mdl;
  Chunk chunk;
  chunk.UserVA = results[0].BaseAddress + results[0].Offset;
  chunk.UserSize = sizeof(struct rcu_shared) + sizeof(struct rcu_slot*) * slots;
  if (!chunk.MapToSystem(pep, &mdl))
    return false;

  auto rs = chunk.Get<struct rcu_shared>();
  if (!rs)
    return false;

  m_chunks.emplace_back(std::move(chunk));
  for (auto slot_index = 0; slot_index < slots; ++slot_index) {
    auto slot_va = reinterpret_cast<uint64_t>(rs->slots_memory[slot_index]);
    auto slot_size = sizeof(rcu_slot) * shm_size;

    chunk.UserVA = slot_va;
    chunk.UserSize = slot_size;
    m_chunks.emplace_back(std::move(chunk));
  }

  if (!m_chunks[0].UnmapFromSystem(&mdl))
    return false;

  m_shm_size = shm_size;
  m_slots = slots;

  return true;
}
#endif // BUILD_USERMODE
