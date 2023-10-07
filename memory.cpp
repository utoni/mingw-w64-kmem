#include <EASTL/finally.h>
#include <cstdint>
#include <eastl_compat.hpp>

#include "memory.hpp"
#include "native.h"

extern "C" {
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

NTSTATUS OpenProcess(_In_ HANDLE pid, _Out_ PEPROCESS *pep, _Out_ HANDLE *obj) {
  NTSTATUS status = PsLookupProcessByProcessId(pid, pep);

  if (NT_SUCCESS(status)) {
    status = ObOpenObjectByPointer(
        *pep, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, GENERIC_ALL,
        *PsProcessType, KernelMode, obj);
  }

  return status;
}

NTSTATUS CloseProcess(_In_ _Out_ PEPROCESS *pep, _In_ _Out_ HANDLE *obj) {
  NTSTATUS status = STATUS_UNSUCCESSFUL;

  if (pep != NULL && obj != NULL) {
    ObDereferenceObject(*pep);
    *pep = NULL;
    status = ZwClose(*obj);
    *obj = NULL;
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
      while (!ldr32->Initialized && waitCount++ < 4) {
        LARGE_INTEGER wait = {.QuadPart = -2500};
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
      while (!ldr->Initialized && waitCount++ < 4) {
        LARGE_INTEGER wait = {.QuadPart = -2500};
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
