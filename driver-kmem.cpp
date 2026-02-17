#include <ntddk.h>

#include <DriverThread.hpp>

#include "ipc.hpp"
#include "memory.hpp"
#include "usermode-ipc.hpp"

using namespace DriverThread;

static Thread thread;

extern "C" {
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

NTSTATUS DriverEntry(_In_ struct _DRIVER_OBJECT *DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  const eastl::array<uint8_t, 10> buffer = {0x41, 0xDE, 0xAD, 0xC0, 0xDE,
                                            0xCA, 0xFE, 0xCA, 0xFE, 0x41};
  const eastl::array<uint8_t, 2> pattern_00 = {0xCA, 0xFE};
  const eastl::array<uint8_t, 2> pattern_01 = {0xFE, 0x41};
  const eastl::array<uint8_t, 1> pattern_02 = {0x41};
  const eastl::array<uint8_t, 10> pattern_03 = {0x41, 0x00, 0x00, 0x00, 0x00,
                                                0x00, 0x00, 0x00, 0x00, 0x41};
  eastl::vector<size_t> found_offsets;

  auto found = PatternScanner::SearchWithMask(
      buffer.data(), eastl::size(buffer), pattern_00.data(),
      eastl::size(pattern_00), "xx", found_offsets);
  if (!found) {
    DbgPrint("%s\n", "First pattern not found!");
    return STATUS_UNSUCCESSFUL;
  }
  found = PatternScanner::SearchWithMask(
      buffer.data(), eastl::size(buffer), pattern_01.data(),
      eastl::size(pattern_01), "xx", found_offsets);
  if (!found) {
    DbgPrint("%s\n", "Second pattern not found!");
    return STATUS_UNSUCCESSFUL;
  }
  found = PatternScanner::SearchWithMask(
      buffer.data(), eastl::size(buffer), pattern_02.data(),
      eastl::size(pattern_02), "x", found_offsets);
  if (!found) {
    DbgPrint("%s\n", "Third pattern not found!");
    return STATUS_UNSUCCESSFUL;
  }
  found = PatternScanner::SearchWithMask(buffer, pattern_03, "x????????x",
                                         found_offsets);
  if (!found) {
    DbgPrint("%s\n", "Fourth pattern not found!");
    return STATUS_UNSUCCESSFUL;
  }
  found = PatternScanner::SearchWithMask(
      buffer, {0xDE, 0xAD, 0x00, 0x00, 0x00, 0x00, 0xCA, 0xFE}, "xx????xx",
      found_offsets);
  if (!found) {
    DbgPrint("%s\n", "Fifth pattern not found!");
    return STATUS_UNSUCCESSFUL;
  }
  for (const auto offset : found_offsets) {
    DbgPrint("Offset: %zu\n", offset);
  }

  DbgPrint("%s\n", "Starting thread..");
  auto args = eastl::make_shared<ThreadArgs>();
  thread.Start(
      [](eastl::shared_ptr<ThreadArgs> args) {
        UNREFERENCED_PARAMETER(args);

        const auto &procs = ::GetProcesses();
        DbgPrint("Got %zu processes on this machine\n", procs.size());
        const wchar_t targetProcess[] = L"explorer.exe";
        const auto &found = eastl::find_if(
            procs.begin(), procs.end(), [&targetProcess](const auto &item) {
              if (item.ProcessName == targetProcess)
                return true;
              return false;
            });
        if (found == procs.end()) {
          DbgPrint("Process not found: '%ws'\n", targetProcess);
          return STATUS_SUCCESS;
        }
        DbgPrint("Process '%ws' pid: %zu\n", targetProcess,
                 found->UniqueProcessId);

        auto pid = reinterpret_cast<HANDLE>(found->UniqueProcessId);
        PEPROCESS pep;
        HANDLE obj;
        if (NT_SUCCESS(::OpenProcess(pid, &pep, &obj))) {
          DbgPrint("Opened process with pid 0x%X\n", pid);
          const auto &mods = ::GetModules(pep, FALSE);
          DbgPrint("Got %zu modules for '%ws'\n", mods.size(), targetProcess);
          for (const auto &mod : mods) {
            DbgPrint("Module: '%ws'\n", mod.BaseDllName.c_str());

            if (mod.BaseDllName == L"Explorer.EXE") {
              DbgPrint("Found explorer module, overwriting 'MZ' with 'FU'..\n");

              UCHAR headerBuf[2] = {0xFF, 0xFF};
              SIZE_T headerOut = sizeof(headerBuf);
              NTSTATUS ret;
              ULONG oldProt = 0;

              ret =
                  ::ReadVirtualMemory(pep, mod.DllBase, headerBuf, &headerOut);
              if (!NT_SUCCESS(ret)) {
                DbgPrint("::ReadVirtualMemory failed with: 0x%lX\n", ret);
              } else {
                DbgPrint("First two bytes of '%ws': %c%c\n", targetProcess,
                         headerBuf[0], headerBuf[1]);
              }

              ret = ::ProtectVirtualMemory(pep, mod.DllBase, 0x2,
                                           PAGE_READWRITE, &oldProt);
              if (!NT_SUCCESS(ret)) {
                DbgPrint("::ProtectVirtualMemory failed with: 0x%lx\n", ret);
              } else {
                DbgPrint("Old page protection (DosHeader): %lu\n", oldProt);
              }

              headerBuf[0] = 0x41;
              headerBuf[1] = 0x41;
              headerOut = sizeof(headerBuf);
              ret =
                  ::WriteVirtualMemory(pep, headerBuf, mod.DllBase, &headerOut);
              if (!NT_SUCCESS(ret)) {
                DbgPrint("::WriteVirtualMemory failed with: 0x%lx\n", ret);
              }

              ret =
                  ::RestoreProtectVirtualMemory(pep, mod.DllBase, 0x2, oldProt);
              if (!NT_SUCCESS(ret)) {
                DbgPrint("::RestoreProtectVirtualMemory failed with: 0x%lx\n",
                         ret);
              }

              headerBuf[0] = 0x00;
              headerBuf[0] = 0x00;
              headerOut = sizeof(headerBuf);
              ret =
                  ::ReadVirtualMemory(pep, mod.DllBase, headerBuf, &headerOut);
              if (!NT_SUCCESS(ret)) {
                DbgPrint("::ReadVirtualMemory failed with: 0x%lX\n", ret);
              } else {
                DbgPrint("First two bytes of '%ws': %c%c\n", targetProcess,
                         headerBuf[0], headerBuf[1]);
              }

              ret = ::ProtectVirtualMemory(pep, mod.DllBase, 0x2,
                                           PAGE_READWRITE, &oldProt);
              if (!NT_SUCCESS(ret)) {
                DbgPrint("::ProtectVirtualMemory failed with: 0x%lx\n", ret);
              } else {
                DbgPrint("Old page protection (DosHeader): %lu\n", oldProt);
              }

              headerBuf[0] = 'M';
              headerBuf[1] = 'Z';
              headerOut = sizeof(headerBuf);
              ret =
                  ::WriteVirtualMemory(pep, headerBuf, mod.DllBase, &headerOut);
              if (!NT_SUCCESS(ret)) {
                DbgPrint("::WriteVirtualMemory failed with: 0x%lx\n", ret);
              }

              ret =
                  ::RestoreProtectVirtualMemory(pep, mod.DllBase, 0x2, oldProt);
              if (!NT_SUCCESS(ret)) {
                DbgPrint("::RestoreProtectVirtualMemory failed with: 0x%lx\n",
                         ret);
              }
            }

            {
              UCHAR headerBuf[4];
              SIZE_T headerOut = sizeof(headerBuf);
              NTSTATUS headerStatus =
                  ::ReadVirtualMemory(pep, mod.DllBase, headerBuf, &headerOut);
              if (!NT_SUCCESS(headerStatus) || headerOut != sizeof(headerBuf)) {
                DbgPrint(
                    "Could not read the first 4 bytes of the image, got %zu "
                    "bytes: 0x%X\n",
                    headerOut, headerStatus);
              } else {
                if (headerBuf[0] != 0x4D || headerBuf[1] != 0x5A ||
                    headerBuf[2] != 0x90 || headerBuf[3] != 0x00) {
                  DbgPrint("Strange, image does not seem to be a PE, first 4 "
                           "bytes: %c%c 0x%X 0x%X\n",
                           headerBuf[0], headerBuf[1], headerBuf[2],
                           headerBuf[3]);
                } else
                  DbgPrint("%s\n", "Explorer.EXE DosHeader restored..");
              }
            }
          }

          const auto &pages = ::GetPages(obj, 64);
          DbgPrint("Got %zu pages\n", pages.size());
          for (const auto &page : pages) {
            DbgPrint("%s\n", page.toString().c_str());
          }

          PatternScanner::ProcessModule scanner(pep, obj, {0x4D, 0x5A, 0x90},
                                                "xxx");
          PatternScanner::ResultVec results;
          auto found = scanner.Scan(L"Explorer.EXE", results);
          if (!found)
            DbgPrint("%s\n", "PatternScanner::ProcessModule was unsuccessful");
          if (results.size() != 1)
            DbgPrint(
                "PatternScanner::ProcessModule was unsuccessful: %zu results\n",
                results.size());
          else
            DbgPrint("PatternScanner::ProcessModule found address for 'MZ\\x90': 0x%p (Offset 0x%p)\n",
                     results[0].BaseAddress + results[0].Offset, results[0].Offset);

          ::CloseProcess(&pep, &obj);
        }

        {
          const auto &procs = ::GetProcesses();
          DbgPrint("Got %zu processes on this machine\n", procs.size());
          const wchar_t targetProcess[] = L"usermode-ipc.exe";
          const auto &found = eastl::find_if(
              procs.begin(), procs.end(), [&targetProcess](const auto &item) {
                if (item.ProcessName == targetProcess)
                  return true;
                return false;
              });
          if (found == procs.end()) {
            DbgPrint("Usermode IPC process not found: '%ws'\n", targetProcess);
            return STATUS_SUCCESS;
          }
          DbgPrint("Process '%ws' pid: %zu\n", targetProcess,
                   found->UniqueProcessId);

          IPC::KernelSharedMemory km;
          if (!km.FindSharedMemory(sizeof(my_slot_data), USERMODE_IPC_SLOTS, *found)) {
            DbgPrint("Shared Memory not found!\n");
            return STATUS_SUCCESS;
          }
          DbgPrint("IPC Memory chunks: %zu\n", km.AmountOfChunks());

          while (km.ProcessEvents(10000LL) != false) {
          }
        }

        DbgPrint("%s\n", "Done.");

        return STATUS_SUCCESS;
      },
      args);

  return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ struct _DRIVER_OBJECT *DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  DbgPrint("%s\n", "Waiting for thread termination..");
  thread.WaitForTermination();
}
}
