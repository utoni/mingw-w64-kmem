#include <EASTL/finally.h>
#include <eastl_compat.hpp>
#include <except.h>

#include "memory.hpp"
#include "native.h"

extern "C" {
NTSTATUS NTAPI WrapperObOpenObjectByPointer(
    _In_ PVOID obj, _In_ ULONG HandleAttributes,
    _In_ PACCESS_STATE PassedAccessState, _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE objType, _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle);

NTSTATUS NTAPI WrapperZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle, _In_ _Out_ PVOID *BaseAddress,
    _In_ _Out_ PSIZE_T NumberOfBytesToProtect, _In_ ULONG NewAccessProtection,
    _Out_ PULONG OldAccessProtection);

NTSTATUS NTAPI WrapperMmCopyVirtualMemory(_In_ PEPROCESS SourceProcess,
                                   _In_ PVOID SourceAddress,
                                   _In_ PEPROCESS TargetProcess,
                                   _In_ PVOID TargetAddress,
                                   _In_ SIZE_T BufferSize,
                                   _In_ KPROCESSOR_MODE PreviousMode,
                                   _Out_ PSIZE_T ReturnSize);

NTKERNELAPI
PPEB NTAPI PsGetProcessPeb(_In_ PEPROCESS Process);

NTSTATUS NTAPI ZwQueryVirtualMemory(_In_ HANDLE ProcessHandle,
                                    _In_ PVOID BaseAddress,
                                    _In_ int MemoryInformationClass,
                                    _Out_ PVOID MemoryInformation,
                                    _In_ SIZE_T MemoryInformationLength,
                                    _Out_ PSIZE_T ReturnLength);

NTSTATUS NTAPI ZwQuerySystemInformation(_In_ int SystemInformationClass,
                                        _Inout_ PVOID SystemInformation,
                                        _In_ ULONG SystemInformationLength,
                                        _Out_opt_ PULONG ReturnLength);

NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(_In_ PEPROCESS Process);
};

static int g_waitCount = 100;
static LONGLONG g_waitTimeout = (-1LL) * 10LL * 1000LL * 250LL; // 250ms

auto get_process_cr3(PEPROCESS pe_process) -> uint64_t
{
    auto process_dirbase = *(uint64_t*)((uint8_t*)pe_process + 0x28);

    if (!process_dirbase)
        return *(uint64_t*)((uint8_t*)pe_process + 0x388);

    return process_dirbase;
}

auto swap_process(PEPROCESS new_process) -> PEPROCESS
{
    auto current_thread = KeGetCurrentThread();

    auto apc_state = *(uint64_t*)((uint64_t)current_thread + 0x98);
    auto old_process = *(uint64_t*)(apc_state + 0x20);

    *(uint64_t*)(apc_state + 0x20) = reinterpret_cast<uint64_t>(new_process);

    auto dir_table_base = get_process_cr3(new_process);
    __writecr3(dir_table_base);

    return reinterpret_cast<PEPROCESS>(old_process);
}

void SetLdrInitWaitPrefs(int waitCount, LONGLONG waitTimeout) {
    g_waitCount = waitCount;
    g_waitTimeout = waitTimeout;
}

eastl::vector<Process> GetProcesses() {
  eastl::vector<Process> result;
  ULONG memoryNeeded = 0;

  if (ZwQuerySystemInformation(SystemProcessInformation, NULL, 0,
                               &memoryNeeded) != STATUS_INFO_LENGTH_MISMATCH ||
      !memoryNeeded) {
    return {};
  }

  auto memory = new uint8_t[memoryNeeded];
  const auto &fnRet = eastl::make_finally([&] { delete[] memory; });

  if (!memory || !NT_SUCCESS(ZwQuerySystemInformation(
                     SystemProcessInformation, memory, memoryNeeded, NULL))) {
    return {};
  }

  result.reserve(memoryNeeded / sizeof(SYSTEM_PROCESS_INFORMATION));
  PSYSTEM_PROCESS_INFORMATION processEntry =
      (PSYSTEM_PROCESS_INFORMATION)memory;
  do {
    Process p;
    p.NumberOfThreads = processEntry->ThreadCount;
    if (processEntry->ProcessName.Length > 0) {
      p.ProcessName = eastl::wstring(processEntry->ProcessName.Buffer);
      // DbgPrint("%ws : %llu\n", p.ProcessName.c_str(),
      // processEntry->ProcessId);
    }
    p.UniqueProcessId = processEntry->ProcessId;
    p.HandleCount = processEntry->HandleCount;
    result.push_back(p);

    processEntry = (PSYSTEM_PROCESS_INFORMATION)((uint8_t *)processEntry +
                                                 processEntry->NextEntryDelta);
  } while (processEntry->NextEntryDelta);

  return result;
}

NTSTATUS OpenProcess(_In_ HANDLE pid, _Out_ PEPROCESS *pep, _Out_ HANDLE *process) {
  NTSTATUS status = PsLookupProcessByProcessId(pid, pep);

  if (NT_SUCCESS(status)) {
    status = WrapperObOpenObjectByPointer(
        *pep, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, GENERIC_ALL | PROCESS_ALL_ACCESS,
        *PsProcessType, KernelMode, process);
  }

  return status;
}

NTSTATUS CloseProcess(_In_ _Out_ PEPROCESS *pep, _In_ _Out_ HANDLE *process) {
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  if (pep != NULL && process != NULL) {
    ObDereferenceObject(*pep);
    *pep = NULL;
    status = ZwClose(*process);
    *process = NULL;
  }

  return status;
}

eastl::vector<Page> GetPages(_In_ HANDLE obj, SIZE_T maxPages,
                             ULONG_PTR startAddress) {
  NTSTATUS status;
  MEMORY_BASIC_INFORMATION memory;
  SIZE_T memoryNeeded = 0;
  eastl::vector<Page> pages;

  do {
    status =
        ZwQueryVirtualMemory(obj, (PVOID)startAddress, MemoryBasicInformation,
                             &memory, sizeof(memory), &memoryNeeded);
    if (!NT_SUCCESS(status) || !memoryNeeded) {
      return pages;
    }

    Page p;
    p.BaseAddress = (uint64_t)memory.BaseAddress;
    p.AllocationBase = (uint64_t)memory.AllocationBase;
    p.AllocationProtect = memory.AllocationProtect;
    p.RegionSize = memory.RegionSize;
    p.State = memory.State;
    p.Protect = memory.Protect;
    p.Type = memory.Type;
    pages.push_back(p);

    startAddress += memory.RegionSize;
  } while (pages.size() < maxPages);

  return pages;
}

eastl::vector<Module> GetModules(_In_ PEPROCESS Process, _In_ BOOLEAN isWow64) {
  KAPC_STATE apcstate;

  KeStackAttachProcess((PKPROCESS)Process, &apcstate);
  const auto &fnRet =
      eastl::make_finally([&] { KeUnstackDetachProcess(&apcstate); });

  eastl::vector<Module> result;
  INT waitCount = 0;

  if (isWow64) {
    PPEB32 peb32 = (PPEB32)PsGetProcessWow64Process(Process);
    if (!peb32) {
      return {};
    }

    PPEB_LDR_DATA32 ldr32 = (PPEB_LDR_DATA32)((ULONG_PTR)peb32->Ldr);
    if (!ldr32) {
      return {};
    }

    if (!ldr32->Initialized) {
      while (!ldr32->Initialized && waitCount++ < g_waitCount) {
        LARGE_INTEGER wait = {.QuadPart = g_waitTimeout};
        KeDelayExecutionThread(KernelMode, TRUE, &wait);
      }

      if (!ldr32->Initialized) {
        return {};
      }
    }

    for (PLIST_ENTRY32 listEntry =
             (PLIST_ENTRY32)((ULONG_PTR)ldr32->InLoadOrderModuleList.Flink);
         listEntry != (PLIST_ENTRY32)((ULONG_PTR)&ldr32->InLoadOrderModuleList);
         listEntry = (PLIST_ENTRY32)((ULONG_PTR)listEntry->Flink)) {

      PLDR_DATA_TABLE_ENTRY32 ldrEntry32 = CONTAINING_RECORD(
          listEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

      Module mod;
      mod.DllBase = ldrEntry32->DllBase;
      mod.EntryPoint = ldrEntry32->EntryPoint;
      mod.SizeOfImage = ldrEntry32->SizeOfImage;
      mod.FullDllName.assign_convert(eastl::u16string(
          (char16_t *)((ULONG_PTR)ldrEntry32->FullDllName.Buffer)));
      mod.BaseDllName.assign_convert(eastl::u16string(
          (char16_t *)((ULONG_PTR)ldrEntry32->BaseDllName.Buffer)));
      mod.Flags = ldrEntry32->Flags;
      mod.LoadCount = ldrEntry32->LoadCount;
      mod.TlsIndex = ldrEntry32->TlsIndex;
      result.emplace_back(mod);
    }
  } else {
    PPEB peb = (PPEB)PsGetProcessPeb(Process);
    if (!peb) {
      return {};
    }

    PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)((ULONG_PTR)peb->Ldr);
    if (!ldr) {
      return {};
    }

    if (!ldr->Initialized) {
      while (!ldr->Initialized && waitCount++ < g_waitCount) {
        LARGE_INTEGER wait = {.QuadPart = g_waitTimeout};
        KeDelayExecutionThread(KernelMode, TRUE, &wait);
      }

      if (!ldr->Initialized) {
        return {};
      }
    }

    for (PLIST_ENTRY64 listEntry =
             (PLIST_ENTRY64)((ULONG_PTR)ldr->InLoadOrderModuleList.Flink);
         listEntry != (PLIST_ENTRY64)((ULONG_PTR)&ldr->InLoadOrderModuleList);
         listEntry = (PLIST_ENTRY64)listEntry->Flink) {

      PLDR_DATA_TABLE_ENTRY ldrEntry64 =
          CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

      Module mod;
      mod.DllBase = (uint64_t)ldrEntry64->DllBase;
      mod.EntryPoint = (uint64_t)ldrEntry64->EntryPoint;
      mod.SizeOfImage = ldrEntry64->SizeOfImage;
      mod.FullDllName.assign_convert(
          eastl::u16string((char16_t *)ldrEntry64->FullDllName.Buffer));
      mod.BaseDllName.assign_convert(
          eastl::u16string((char16_t *)ldrEntry64->BaseDllName.Buffer));
      mod.Flags = ldrEntry64->Flags;
      mod.LoadCount = ldrEntry64->LoadCount;
      mod.TlsIndex = ldrEntry64->TlsIndex;
      result.emplace_back(mod);
    }
  }

  return result;
}

extern "C" int ehandler(_In_ EXCEPTION_POINTERS *ep) {
  (void)ep;
  return EXCEPTION_EXECUTE_HANDLER;
}

NTSTATUS ProtectVirtualMemory(_In_ PEPROCESS pep,
                              _In_ uint64_t addr,
                              _In_ SIZE_T size, _In_ ULONG newProt,
                              _Out_ ULONG *oldProt) {
  KAPC_STATE apcState;
  NTSTATUS status;
  PVOID paddr = (PVOID)addr;
  SIZE_T psize = size;
  ULONG prot = 0;

  KeStackAttachProcess((PKPROCESS)pep, &apcState);

  __dpptry(ehandler, pvm) {
    status =
        WrapperZwProtectVirtualMemory(ZwCurrentProcess(), &paddr, &psize, newProt, &prot);
    *oldProt = prot;
  }
  __dppexcept(pvm) { status = STATUS_ACCESS_VIOLATION; }
  __dpptryend(pvm);

  KeUnstackDetachProcess(&apcState);

  return status;
}

NTSTATUS RestoreProtectVirtualMemory(_In_ PEPROCESS pep, _In_ uint64_t addr,
                                     _In_ SIZE_T siz, _In_ ULONG old_prot) {
  KAPC_STATE apcState;
  NTSTATUS status;
  PVOID paddr = (PVOID)addr;
  SIZE_T psize = siz;
  ULONG prot = 0;

  KeStackAttachProcess((PKPROCESS)pep, &apcState);

  __dpptry(ehandler, rpvm) {
    status =
        WrapperZwProtectVirtualMemory(ZwCurrentProcess(), &paddr, &psize, old_prot, &prot);
  }
  __dppexcept(rpvm) { status = STATUS_ACCESS_VIOLATION; }
  __dpptryend(rpvm);

  KeUnstackDetachProcess(&apcState);

  return status;
}

NTSTATUS ReadVirtualMemory(_In_ PEPROCESS pep, _In_ uint64_t sourceAddress,
                           _In_ UCHAR *targetAddress, _In_ _Out_ SIZE_T *size) {
  NTSTATUS status = STATUS_SUCCESS;
  SIZE_T bytes = 0;

  __dpptry(ehandler, rvm) {
    status =
        WrapperMmCopyVirtualMemory(pep, (PVOID)sourceAddress, PsGetCurrentProcess(),
                            (PVOID)targetAddress, *size, KernelMode, &bytes);
  }
  __dppexcept(rvm) { status = STATUS_UNSUCCESSFUL; }
  __dpptryend(rvm);

  *size = bytes;

  return status;
}

NTSTATUS WriteVirtualMemory(_In_ PEPROCESS pep, _In_ const UCHAR *sourceAddress,
                            _In_ _Out_ uint64_t targetAddress,
                            _In_ _Out_ SIZE_T *size) {
  NTSTATUS status = STATUS_SUCCESS;
  SIZE_T bytes = 0;

  __dpptry(ehandler, wvm) {
    status =
        WrapperMmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)sourceAddress, pep,
                            (PVOID)targetAddress, *size, KernelMode, &bytes);
  }
  __dppexcept(wvm) { status = STATUS_UNSUCCESSFUL; }
  __dpptryend(wvm);

  *size = bytes;

  return status;
}
