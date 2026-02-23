#include <EASTL/algorithm.h>
#include <EASTL/finally.h>
#include <EASTL/shared_ptr.h>
#include <eastl_compat.hpp>
#include <except.h>

#include "memory.hpp"
#include "native.h"

#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180
#define WINDOWS_22H2 19045

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

NTSTATUS NTAPI WrapperZwCreateFile(
    _Out_ PHANDLE FileHandle, _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _Out_ PIO_STATUS_BLOCK StatusBlock, _In_ PLARGE_INTEGER AllocationSize,
    _In_ ULONG FileAttributes, _In_ ULONG ShareAccess,
    _In_ ULONG CreateDisposition, _In_ ULONG CreateOptions, _In_ PVOID EaBuffer,
    _In_ ULONG EaLength);

NTSTATUS NTAPI WrapperZwClose(_In_ HANDLE Handle);

NTSTATUS NTAPI WrapperZwWriteFile(_In_ HANDLE FileHandle, _In_ HANDLE Event,
                                  _In_ PIO_APC_ROUTINE ApcRoutine,
                                  _In_ PVOID ApcContext,
                                  _Out_ PIO_STATUS_BLOCK StatusBlock,
                                  _In_ PVOID Buffer, _In_ ULONG Length,
                                  _In_ PLARGE_INTEGER ByteOffset,
                                  _In_ PULONG Key);

PVOID NTAPI MmMapIoSpaceEx(_In_ PHYSICAL_ADDRESS PhysicalAddress,
                           _In_ SIZE_T NumberOfBytes, _In_ ULONG Protect);

NTSTATUS NTAPI MmCopyMemory(_In_ PVOID TargetAddress,
                            _In_ MM_COPY_ADDRESS SourceAddress,
                            _In_ SIZE_T NumberOfBytes, _In_ ULONG Flags,
                            _Out_ PSIZE_T NumberOfBytesTransferred);

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

#ifdef ENABLE_EXPERIMENTAL
uint64_t Experimental::GetProcessCr3(_In_ const PEPROCESS pe_process) {
  PUCHAR process = (PUCHAR)pe_process;
  ULONG_PTR process_dirbase =
      *(PULONG_PTR)(process + 0x28); // dirbase x64, 32bit is 0x18
  if (process_dirbase == 0) {
    uint64_t UserDirOffset = Experimental::GetUserDirectoryTableBaseOffset();

    ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
    return process_userdirbase;
  }
  return process_dirbase;
}

PEPROCESS Experimental::SwapProcess(_In_ PEPROCESS new_process) {
  auto current_thread = KeGetCurrentThread();

  auto apc_state = *(uint64_t *)((uint64_t)current_thread + 0x98);
  auto old_process = *(uint64_t *)(apc_state + 0x20);

  *(uint64_t *)(apc_state + 0x20) = reinterpret_cast<uint64_t>(new_process);

  auto dir_table_base = GetProcessCr3(new_process);
  __writecr3(dir_table_base);

  return reinterpret_cast<PEPROCESS>(old_process);
}

uint64_t Experimental::GetUserDirectoryTableBaseOffset() {
  RTL_OSVERSIONINFOW ver = {};
  RtlGetVersion(&ver);
  switch (ver.dwBuildNumber) {
  case WINDOWS_1803:
    return 0x0278;
    break;
  case WINDOWS_1809:
    return 0x0278;
    break;
  case WINDOWS_1903:
    return 0x0280;
    break;
  case WINDOWS_1909:
    return 0x0280;
    break;
  case WINDOWS_2004:
    return 0x0388;
    break;
  case WINDOWS_20H2:
    return 0x0388;
    break;
  case WINDOWS_21H1:
    return 0x0388;
    break;
  case WINDOWS_22H2:
    return 0x0388;
    break;
  default:
    return 0x0388;
  }
}

NTSTATUS Experimental::ReadPhysicalAddress(_In_ PVOID TargetAddress,
                                           _In_ PVOID lpBuffer,
                                           _In_ SIZE_T Size,
                                           _Out_ SIZE_T *BytesRead) {
  MM_COPY_ADDRESS AddrToRead = {};
  AddrToRead.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
  return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL,
                      BytesRead);
}

NTSTATUS Experimental::WritePhysicalAddress(_In_ PVOID TargetAddress,
                                            _In_ PVOID lpBuffer,
                                            _In_ SIZE_T Size,
                                            _Out_ SIZE_T *BytesWritten) {
  if (!TargetAddress)
    return STATUS_UNSUCCESSFUL;

  PHYSICAL_ADDRESS AddrToWrite = {};
  AddrToWrite.QuadPart = LONGLONG(TargetAddress);

  PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

  if (!pmapped_mem)
    return STATUS_UNSUCCESSFUL;

  memcpy(pmapped_mem, lpBuffer, Size);

  *BytesWritten = Size;
  MmUnmapIoSpace(pmapped_mem, Size);
  return STATUS_SUCCESS;
}

uint64_t Experimental::GetKernelDirBase() {
  PUCHAR process = (PUCHAR)PsGetCurrentProcess();
  ULONG_PTR cr3 = *(PULONG_PTR)(process + 0x28); // dirbase x64, 32bit is 0x18
  return cr3;
}

uint64_t Experimental::TranslateLinearAddress(_In_ uint64_t directoryTableBase,
                                              _In_ uint64_t virtualAddress) {
  directoryTableBase &= ~0xf;

  UINT64 pageOffset =
      virtualAddress & ~(~0ul << Experimental::page_offset_size);
  UINT64 pte = ((virtualAddress >> 12) & (0x1ffll));
  UINT64 pt = ((virtualAddress >> 21) & (0x1ffll));
  UINT64 pd = ((virtualAddress >> 30) & (0x1ffll));
  UINT64 pdp = ((virtualAddress >> 39) & (0x1ffll));

  SIZE_T readsize = 0;
  UINT64 pdpe = 0;
  ReadPhysicalAddress(PVOID(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe),
                      &readsize);
  if (~pdpe & 1)
    return 0;

  UINT64 pde = 0;
  ReadPhysicalAddress(PVOID((pdpe & Experimental::page_mask) + 8 * pd), &pde,
                      sizeof(pde), &readsize);
  if (~pde & 1)
    return 0;

  /* 1GB large page, use pde's 12-34 bits */
  if (pde & 0x80)
    return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

  UINT64 pteAddr = 0;
  ReadPhysicalAddress(PVOID((pde & Experimental::page_mask) + 8 * pt), &pteAddr,
                      sizeof(pteAddr), &readsize);
  if (~pteAddr & 1)
    return 0;

  /* 2MB large page */
  if (pteAddr & 0x80)
    return (pteAddr & Experimental::page_mask) +
           (virtualAddress & ~(~0ull << 21));

  virtualAddress = 0;
  ReadPhysicalAddress(PVOID((pteAddr & Experimental::page_mask) + 8 * pte),
                      &virtualAddress, sizeof(virtualAddress), &readsize);
  virtualAddress &= Experimental::page_mask;

  if (!virtualAddress)
    return 0;

  return virtualAddress + pageOffset;
}

NTSTATUS Experimental::WriteProcessMemory(_In_ HANDLE pid,
                                          _In_ uint64_t Address,
                                          _In_ uint64_t AllocatedBuffer,
                                          _In_ SIZE_T size,
                                          _Out_ SIZE_T *written) {
  DbgPrintEx(0, 0, "\n[Write] Address is: %llx", Address);
  PEPROCESS pProcess = NULL;
  if (pid == NULL)
    return STATUS_UNSUCCESSFUL;

  NTSTATUS NtRet = PsLookupProcessByProcessId(pid, &pProcess);
  if (NtRet != STATUS_SUCCESS)
    return NtRet;

  ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
  ObDereferenceObject(pProcess);
  DbgPrintEx(0, 0, "\n[Write] DirBase is: %llx", process_dirbase);
  SIZE_T CurOffset = 0;
  SIZE_T TotalSize = size;
  while (TotalSize) {
    uint64_t CurPhysAddr =
        TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
    if (!CurPhysAddr)
      return STATUS_UNSUCCESSFUL;

    ULONG64 WriteSize = MIN(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
    SIZE_T BytesWritten = 0;
    NtRet = WritePhysicalAddress((PVOID)CurPhysAddr,
                                 (PVOID)((ULONG64)AllocatedBuffer + CurOffset),
                                 WriteSize, &BytesWritten);
    TotalSize -= BytesWritten;
    CurOffset += BytesWritten;
    if (NtRet != STATUS_SUCCESS)
      break;
    if (BytesWritten == 0)
      break;
  }

  *written = CurOffset;
  return NtRet;
}

NTSTATUS Experimental::ReadProcessMemory(_In_ HANDLE pid, _In_ uint64_t Address,
                                         _In_ uint64_t AllocatedBuffer,
                                         _In_ SIZE_T size, _Out_ SIZE_T *read) {
  DbgPrintEx(0, 0, "\n[Read] Address is: %llx", Address);
  PEPROCESS pProcess = NULL;
  if (pid == NULL)
    return STATUS_UNSUCCESSFUL;

  NTSTATUS NtRet = PsLookupProcessByProcessId(pid, &pProcess);
  if (NtRet != STATUS_SUCCESS)
    return NtRet;

  ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
  DbgPrintEx(0, 0, "\n[Read] DirBase is: %llx", process_dirbase);
  ObDereferenceObject(pProcess);

  SIZE_T CurOffset = 0;
  SIZE_T TotalSize = size;
  while (TotalSize) {
    uint64_t CurPhysAddr =
        TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
    if (!CurPhysAddr)
      return STATUS_UNSUCCESSFUL;

    ULONG64 ReadSize = MIN(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
    SIZE_T BytesRead = 0;
    NtRet = ReadPhysicalAddress((PVOID)CurPhysAddr,
                                (PVOID)((ULONG64)AllocatedBuffer + CurOffset),
                                ReadSize, &BytesRead);
    TotalSize -= BytesRead;
    CurOffset += BytesRead;
    if (NtRet != STATUS_SUCCESS)
      break;
    if (BytesRead == 0)
      break;
  }

  *read = CurOffset;
  return NtRet;
}

uint64_t
Experimental::VirtualAddressToPhysicalAddress(_In_ PVOID VirtualAddress) {
  return MmGetPhysicalAddress(VirtualAddress).QuadPart;
}

uint64_t
Experimental::PhysicalAddressToVirtualAddress(_In_ uint64_t PhysicalAddress) {
  PHYSICAL_ADDRESS PhysicalAddr = {};
  PhysicalAddr.QuadPart = PhysicalAddress;

  return reinterpret_cast<uint64_t>(MmGetVirtualForPhysical(PhysicalAddr));
}
#endif

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

NTSTATUS OpenProcess(_In_ HANDLE pid, _Out_ PEPROCESS *pep,
                     _Out_ HANDLE *process) {
  NTSTATUS status = PsLookupProcessByProcessId(pid, pep);

  if (NT_SUCCESS(status)) {
    status = WrapperObOpenObjectByPointer(
        *pep, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL,
        GENERIC_ALL | PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, process);
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

NTSTATUS ProtectVirtualMemory(_In_ PEPROCESS pep, _In_ uint64_t addr,
                              _In_ SIZE_T size, _In_ ULONG newProt,
                              _Out_ ULONG *oldProt) {
  KAPC_STATE apcState;
  NTSTATUS status;
  PVOID paddr = (PVOID)addr;
  SIZE_T psize = size;
  ULONG prot = 0;

  KeStackAttachProcess((PKPROCESS)pep, &apcState);

  __dpptry(ehandler, pvm) {
    status = WrapperZwProtectVirtualMemory(ZwCurrentProcess(), &paddr, &psize,
                                           newProt, &prot);
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
    status = WrapperZwProtectVirtualMemory(ZwCurrentProcess(), &paddr, &psize,
                                           old_prot, &prot);
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
    status = WrapperMmCopyVirtualMemory(
        pep, (PVOID)sourceAddress, PsGetCurrentProcess(), (PVOID)targetAddress,
        *size, KernelMode, &bytes);
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
    status = WrapperMmCopyVirtualMemory(
        PsGetCurrentProcess(), (PVOID)sourceAddress, pep, (PVOID)targetAddress,
        *size, KernelMode, &bytes);
  }
  __dppexcept(wvm) { status = STATUS_UNSUCCESSFUL; }
  __dpptryend(wvm);

  *size = bytes;

  return status;
}

bool FileLogger::Init(const eastl::wstring &path, bool exclusive, bool append) {
  OBJECT_ATTRIBUTES obj_attr;
  UNICODE_STRING file_name;
  NTSTATUS status;

  if (m_handle != nullptr)
    return false;

  m_path = path;
  if (m_path.empty())
    return false;

  RtlInitUnicodeString(&file_name, m_path.c_str());

  InitializeObjectAttributes(&obj_attr, &file_name,
                             OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                             NULL);
  status =
      WrapperZwCreateFile(&m_handle, GENERIC_WRITE | (append ? FILE_APPEND_DATA : 0), &obj_attr, &m_io_status,
                          NULL, FILE_ATTRIBUTE_NORMAL, (exclusive ? 0 : FILE_SHARE_READ), FILE_OVERWRITE_IF,
                          FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
  if (!NT_SUCCESS(status))
    return false;

  return true;
}

bool FileLogger::Close() {
  if (m_handle == nullptr)
    return false;

  if (m_path.empty())
    return false;

  WrapperZwClose(m_handle);
  m_handle = nullptr;
  return true;
}

bool FileLogger::WriteString(eastl::string &&write_buffer) {
  NTSTATUS status = WrapperZwWriteFile(m_handle, NULL, NULL, NULL, &m_io_status,
                                       (void *)write_buffer.c_str(),
                                       write_buffer.length(), NULL, NULL);
  if (!NT_SUCCESS(status))
    return false;

  return true;
}

bool PatternScanner::SearchWithMask(const uint8_t *buffer, size_t buffer_size,
                                    const uint8_t *pattern, size_t pattern_size,
                                    const eastl::string_view &mask,
                                    eastl::vector<size_t> &offsets) {
  bool found_some = false;

  if (mask.length() != pattern_size)
    return false;

  for (size_t i = 0; i < buffer_size - pattern_size + 1; ++i) {
    bool match = true;
    for (size_t j = 0; j < pattern_size; ++j) {
      if (mask[j] == 'x' && buffer[i + j] != pattern[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      found_some = true;
      offsets.push_back(i);
    }
  }

  return found_some;
}

bool PatternScanner::Page::Scan(const PageSelectorCallback & selector_cb,
                                ResultVec &results, size_t max_results) {
  if (eastl::size(m_pattern) > 64)
    return false;

  auto pages = ::GetPages(m_obj, m_max_pages);
  auto page_iter = pages.begin();
  while (page_iter != pages.end()) {
    if (!selector_cb(*page_iter))
      page_iter = pages.erase(page_iter);
    else
      page_iter++;
  }
  if (pages.size() == 0)
    return false;

  eastl::vector<size_t> offsets;
  auto copy_buffer = eastl::make_shared<eastl::array<uint8_t, 4096 * 8>>();
  for (const auto page : pages) {
    Result result;
    result.BaseAddress = page.BaseAddress;
    SIZE_T offset = 0;
    while (offset < page.RegionSize - eastl::size(m_pattern) + 1) {
      SIZE_T in_out_size =
          eastl::min(eastl::size(*copy_buffer), page.RegionSize - offset);
      const auto ret =
          ::ReadVirtualMemory(m_pep, page.BaseAddress + offset,
                              eastl::begin(*copy_buffer), &in_out_size);
      if (!NT_SUCCESS(ret) || in_out_size == 0)
        break;

      if (SearchWithMask(eastl::begin(*copy_buffer), in_out_size,
                         m_pattern.begin(), eastl::size(m_pattern), m_mask,
                         offsets)) {
        if (offsets.size() >= max_results)
          return false;
        for (const auto& offset : offsets) {
          result.Offset = offset;
          results.emplace_back(result);
        }
        offsets.clear();
      }

      offset += in_out_size - eastl::size(m_pattern) + 1;
    }
  }

  return true;
}

bool PatternScanner::ProcessModule::Scan(const eastl::wstring_view &module_name,
                                         ResultVec &results,
                                         size_t max_results) {
  if (eastl::size(m_pattern) > 64)
    return false;

  const auto mods = ::GetModules(m_pep, FALSE);
  const auto mod = eastl::find_if(mods.begin(), mods.end(),
                                  [&module_name](const Module &mod) {
                                    return mod.BaseDllName == module_name;
                                  });
  if (mod == mods.end())
    return false;

  eastl::vector<size_t> offsets;
  auto copy_buffer = eastl::make_shared<eastl::array<uint8_t, 4096 * 8>>();
  const auto pages = ::GetPages(m_obj, m_max_pages);
  for (const auto page : pages) {
    if (page.BaseAddress < mod->DllBase ||
        page.BaseAddress + page.RegionSize > mod->DllBase + mod->SizeOfImage)
      continue;
    Result result;
    result.BaseAddress = page.BaseAddress;
    SIZE_T offset = 0;
    while (offset < page.RegionSize - eastl::size(m_pattern) + 1) {
      SIZE_T in_out_size =
          eastl::min(eastl::size(*copy_buffer), page.RegionSize - offset);
      const auto ret =
          ::ReadVirtualMemory(m_pep, page.BaseAddress + offset,
                              eastl::begin(*copy_buffer), &in_out_size);
      if (!NT_SUCCESS(ret) || in_out_size == 0)
        break;

      if (SearchWithMask(eastl::begin(*copy_buffer), in_out_size,
                         m_pattern.begin(), eastl::size(m_pattern), m_mask,
                         offsets)) {
        if (offsets.size() >= max_results)
          return false;
        for (const auto& offset : offsets) {
          result.Offset = offset;
          results.emplace_back(result);
        }
        offsets.clear();
      }

      offset += in_out_size - eastl::size(m_pattern) + 1;
    }
  }

  return true;
}
