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
    volatile long int opened_by_kernel;
    volatile long int user_wants_shutdown;
    volatile long long int active;
    struct rcu_slot* slots_memory[0];
  };

#ifdef BUILD_USERMODE
  typedef LONG (*PVECTORED_EXCEPTION_HANDLER)(_In_ _EXCEPTION_POINTERS *ExceptionInfo);

  extern VOID Sleep(_In_ unsigned int dwMilliseconds);
  extern void* VirtualAlloc(void* lpAddress, size_t dwSize, unsigned int flAllocationType,
                            unsigned int flProtect);
  extern BOOL VirtualFree(_In_ PVOID lpAddress, _In_ SIZE_T dwSize, unsigned int dwFreeType);
  extern PVOID AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
  extern ULONG RemoveVectoredExceptionHandler(PVOID handle);
  extern PVOID CreateMutexA(_In_ PVOID lpMutexAttributes, _In_ BOOL bInitialOwner,
                            _In_ LPCSTR lpName);
  extern unsigned int WaitForSingleObject(_In_ HANDLE hHandle, _In_ unsigned int dwMilliseconds);
  extern BOOL ReleaseMutex(_In_ HANDLE hMutex);
#endif
}

#ifdef BUILD_USERMODE
extern "C" {
  static struct {
    volatile LONG initialized = 0;
    HANDLE mtx = NULL;
    PVOID handle = NULL;
    UserSharedMemory * shm = NULL;
  } g_exceptionHandlers;

  static LONG ExceptionHandler(_In_ _EXCEPTION_POINTERS *ExceptionInfo) {
    (void)ExceptionInfo;

    if (g_exceptionHandlers.mtx != NULL
        && ::WaitForSingleObject(g_exceptionHandlers.mtx, (unsigned int)-1) != 0)
    {
      return EXCEPTION_CONTINUE_EXECUTION;
    }

    g_exceptionHandlers.shm->RequestShutdown();
    while (g_exceptionHandlers.shm->OpenedByKernel())
      Sleep(100);

    if (g_exceptionHandlers.mtx != NULL)
      ::ReleaseMutex(g_exceptionHandlers.mtx);
    return EXCEPTION_CONTINUE_SEARCH;
  }

  static void DeleteExceptionHandler();

  static bool SetupExceptionHandlerOnce(UserSharedMemory * shm) {
    if (InterlockedExchange(&g_exceptionHandlers.initialized, 1) != 0)
      return false; // Only one instance per process allowed!

    if (g_exceptionHandlers.mtx == NULL)
      g_exceptionHandlers.mtx = ::CreateMutexA(NULL, FALSE, NULL);
    if (g_exceptionHandlers.mtx == NULL) {
      DeleteExceptionHandler();
      return false;
    }

    g_exceptionHandlers.shm = shm;
    g_exceptionHandlers.handle = ::AddVectoredExceptionHandler(1, ExceptionHandler);
    if (g_exceptionHandlers.handle == NULL) {
      DeleteExceptionHandler();
      return false;
    }

    return true;
  }

  static void DeleteExceptionHandler() {
    if (InterlockedExchange(&g_exceptionHandlers.initialized, 0) == 0)
      return;

    if (g_exceptionHandlers.mtx != NULL
        && ::WaitForSingleObject(g_exceptionHandlers.mtx, (unsigned int)-1) != 0)
    {
      return;
    }

    if (g_exceptionHandlers.handle != NULL)
      ::RemoveVectoredExceptionHandler(g_exceptionHandlers.handle);
    g_exceptionHandlers.handle = NULL;
    g_exceptionHandlers.shm = NULL;
    if (g_exceptionHandlers.mtx != NULL)
      ::ReleaseMutex(g_exceptionHandlers.mtx);
  }
}


UserSharedMemory::UserSharedMemory() : m_shm_size{0}, m_slots{0}, m_memory{nullptr} {
}

UserSharedMemory::~UserSharedMemory() {
  RequestShutdown();
  while (OpenedByKernel())
    Sleep(100);
  DeleteExceptionHandler();
  ::VirtualFree(m_memory, sizeof(rcu_shared) + sizeof(void*) * m_slots, MEM_RELEASE);
  m_memory = nullptr;
}

bool UserSharedMemory::Allocate(std::size_t shm_size, std::size_t slots) {
  if (m_memory)
    return false; // Already initialized
  if (!SetupExceptionHandlerOnce(this))
    return false;

  m_memory = ::VirtualAlloc(NULL, sizeof(rcu_shared) + sizeof(void*) * slots,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!m_memory)
    return false;

  auto rcu_shared = reinterpret_cast<struct rcu_shared*>(m_memory);
  m_shm_size = shm_size;
  m_slots = slots;
  rcu_shared->opened_by_kernel = 0;
  rcu_shared->user_wants_shutdown = 0;
  rcu_shared->active = 0;

  for (auto i = 0; i < slots; ++i) {
    rcu_shared->slots_memory[i] = reinterpret_cast<struct rcu_slot*>(VirtualAlloc(nullptr, sizeof(rcu_slot) + shm_size,
                                                                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  }
  for (auto i = 0; i < slots; ++i) {
    if (!rcu_shared->slots_memory[i])
      return false;
  }

  ::memcpy(rcu_shared->magic, magic.begin(), magic_size); // Kernel may now find this shared memory!

  return true;
}

void UserSharedMemory::RequestShutdown() {
  auto rcu_shared = reinterpret_cast<struct rcu_shared*>(m_memory);
  if (rcu_shared)
    InterlockedExchange(&rcu_shared->user_wants_shutdown, 1);
}

bool UserSharedMemory::OpenedByKernel() {
  auto rcu_shared = reinterpret_cast<struct rcu_shared*>(m_memory);
  if (rcu_shared)
    return InterlockedCompareExchange(&rcu_shared->opened_by_kernel, 0, 0) != 0;
  return false;
}

bool UserSharedMemory::ShutdownRequested() {
  auto rcu_shared = reinterpret_cast<struct rcu_shared*>(m_memory);
  if (rcu_shared)
    return InterlockedCompareExchange(&rcu_shared->user_wants_shutdown, 0, 0) != 0;
  return false;
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

KernelSharedMemory::Chunk::Chunk(Chunk && other) {
  Memory = other.Memory;
  Mdl = other.Mdl;
  Type = other.Type;
  UserVA = other.UserVA;
  UserSize = other.UserSize;

  other.Memory = nullptr;
  other.Mdl = nullptr;
  other.Type = IS_INVALID;
}

KernelSharedMemory::Chunk::~Chunk() {
  UnmapFromSystem();
  UserVA = 0;
  UserSize = 0;
}

bool KernelSharedMemory::Chunk::MapToSystem(_In_ PEPROCESS pep) {
  PVOID kernel_va;
  KAPC_STATE apc;

  if (Type != IS_INVALID)
    return false;

  Mdl = IoAllocateMdl(
    reinterpret_cast<void*>(UserVA), UserSize,
    FALSE, FALSE, NULL
  );
  if (!Mdl)
    return false;

  KeStackAttachProcess((PKPROCESS)pep, &apc);

  bool failed = false;
  __dpptry(map_exception_handler, map_seh) {
    MmProbeAndLockPages(
      Mdl,
      UserMode,
      IoModifyAccess
    );
  }
  __dppexcept(map_seh) { failed = true; }
  __dpptryend(map_seh);

  KeUnstackDetachProcess(&apc);
  if (failed) {
    IoFreeMdl(Mdl);
    Mdl = nullptr;
    return false;
  }

  kernel_va = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
  if (!kernel_va) {
    if (Mdl->MdlFlags & MDL_PAGES_LOCKED)
      MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);
    Mdl = nullptr;
    return false;
  }

  Memory = kernel_va;
  Type = IS_MAPPED;
  return true;
}

bool KernelSharedMemory::Chunk::UnmapFromSystem() {
  if (Type != IS_MAPPED)
    return false;
  Type = IS_INVALID;

  if (Mdl) {
    if (Mdl->MdlFlags & MDL_PAGES_LOCKED)
      MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);
    Mdl = nullptr;
  }

  Memory = nullptr;
  return true;
}

KernelSharedMemory::KernelSharedMemory()
  : m_shm_size{0}, m_slots{0}, m_pep{nullptr}, m_obj{nullptr}, m_chunks{} {
}

KernelSharedMemory::~KernelSharedMemory() {
  ShutdownImmediately();
}

bool KernelSharedMemory::FindSharedMemory(std::size_t shm_size, std::size_t slots,
                                          const Process& target_proc) {
  auto pid = reinterpret_cast<HANDLE>(target_proc.UniqueProcessId);

  if (!NT_SUCCESS(::OpenProcess(pid, &m_pep, &m_obj))) {
    m_pep = nullptr;
    m_obj = nullptr;
    return false;
  }

  PatternScanner::Page scanner(m_pep, m_obj, magic, magic_mask);
  PatternScanner::ResultVec results;
  auto found = scanner.Scan([](const Page & page) {
    return page.BaseAddress < 0x00007FF000000000 && (page.Type & MEM_PRIVATE) != 0;
  }, results, 2);
  if (!found)
    return false;
  if (results.size() != 1)
    return false;

  Chunk chunk;
  chunk.UserVA = results[0].BaseAddress + results[0].Offset;
  chunk.UserSize = sizeof(struct rcu_shared) + sizeof(struct rcu_slot*) * slots;
  if (!chunk.MapToSystem(m_pep))
    return false;

  auto rs = chunk.Get<struct rcu_shared>();
  if (!rs)
    return false;
  InterlockedExchange(&rs->opened_by_kernel, 1);

  m_chunks.emplace_back(std::move(chunk));

  for (auto slot_index = 0; slot_index < slots; ++slot_index) {
    auto slot_va = reinterpret_cast<uint64_t>(rs->slots_memory[slot_index]);
    auto slot_size = sizeof(rcu_slot) * shm_size;

    chunk.UserVA = slot_va;
    chunk.UserSize = slot_size;
    if (!chunk.MapToSystem(m_pep))
      continue;
    m_chunks.emplace_back(std::move(chunk));
  }

  m_shm_size = shm_size;
  m_slots = slots;

  return true;
}

bool KernelSharedMemory::ProcessEvents(long long int wait_time) {
  if (m_chunks.size() < 1)
    return false;

  auto rs = m_chunks[0].Get<struct rcu_shared>();
  if (!rs)
    return false;

  {
    auto user_wants_shutdown = InterlockedCompareExchange(&rs->user_wants_shutdown, 0, 0);
    if (user_wants_shutdown != 0) {
      ShutdownImmediately();
      return false;
    }
  }

  if (wait_time > 0) {
    LARGE_INTEGER wait = {.QuadPart = (-1LL) * (wait_time)};
    KeDelayExecutionThread(KernelMode, FALSE, &wait);

    auto user_wants_shutdown = InterlockedCompareExchange(&rs->user_wants_shutdown, 0, 0);
    if (user_wants_shutdown != 0) {
      ShutdownImmediately();
      return false;
    }
  }

  return true;
}

bool KernelSharedMemory::ShutdownImmediately() {
  if (!m_pep || !m_obj || m_chunks.size() < 1)
    return false;

  auto rs = m_chunks[0].Get<struct rcu_shared>();
  if (!rs)
    return false;
  m_chunks.clear();
  InterlockedExchange(&rs->opened_by_kernel, 0);

  ::CloseProcess(&m_pep, &m_obj);
  m_pep = nullptr;
  m_obj = nullptr;

  return true;
}
#endif // BUILD_USERMODE
