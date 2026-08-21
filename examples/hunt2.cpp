#include <ntddk.h>

#include <DriverThread.hpp>
#include <EASTL/algorithm.h>
#include <EASTL/array.h>
#include <EASTL/unordered_map.h>
#include <eastl_compat.hpp>
#include <except.h>
#include <obfuscate.hpp>

#include "memory.hpp"
#include "stringify.hpp"

#define STRNCMP_CR(haystack, needle)                                           \
  (strncasecmp(haystack, skCrypt(needle), sizeof(needle) - 1))

using namespace DriverThread;

static Thread thread;
static Event shutdown_event;
#ifdef HUNT2_DEBUG
static FileLogger logger;
#endif
static auto targetProcess = skCrypt(L"HuntGame.exe");
static auto targetModule = skCrypt(L"GameHunt.dll");

static uint64_t SearchHuntProcess(void) {
  const auto &procs = ::GetProcesses();
  const auto &found =
      eastl::find_if(procs.begin(), procs.end(), [](const auto &item) {
        if (item.ProcessName == targetProcess)
          return true;
        return false;
      });

  if (found == procs.end()) {
    return 0;
  }

  return found->UniqueProcessId;
}

extern "C" {
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

int mainloop_exception_handler(_In_ EXCEPTION_POINTERS *lpEP) {
  (void)lpEP;
  return EXCEPTION_EXECUTE_HANDLER;
}

int unload_exception_handler(_In_ EXCEPTION_POINTERS *lpEP) {
  (void)lpEP;
  return EXCEPTION_EXECUTE_HANDLER;
}

NTSTATUS DriverEntry(_In_ struct _DRIVER_OBJECT *DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  thread.Start(
      [](eastl::shared_ptr<ThreadArgs> args) {
        UNREFERENCED_PARAMETER(args);

        HANDLE hunt_pid = NULL;
        PEPROCESS pep = NULL;
        HANDLE obj = NULL;
        uint64_t base = 0;
        LONGLONG wait_timeout = (-1LL) * 10LL * 1000LL * 250LL;
#ifdef HUNT2_DEBUG
        size_t cur_iter = 0;
        const size_t print_every = 50;
        eastl::unordered_map<eastl::string, size_t> objects_found;
        eastl::unordered_map<uint64_t, size_t> render_nodes_found;

        logger.Init(L"\\??\\C:\\ht2dbg.log");
        logger.Write("Init.\n");
#endif

        DbgPrint("%s\n", "start");
        __dpptry(mainloop_exception_handler, mainloop_seh) {
          while (shutdown_event.Wait(wait_timeout) == STATUS_TIMEOUT) {
            if (!hunt_pid) {
              wait_timeout = (-1LL) * 10LL * 1000LL * 1000LL;
              hunt_pid = reinterpret_cast<HANDLE>(SearchHuntProcess());
              if (hunt_pid == NULL) {
                continue;
              }
              DbgPrint(skCrypt("pid: %p\n"), hunt_pid);

#ifdef HUNT2_DEBUG
              cur_iter = 0;
              objects_found.clear();
              render_nodes_found.clear();
#endif

              if (!NT_SUCCESS(::OpenProcess(hunt_pid, &pep, &obj))) {
                hunt_pid = NULL;
                continue;
              }

              base = 0;
              while (!base && hunt_pid) {
                LARGE_INTEGER wait = {.QuadPart =
                                          (-1LL) * 10LL * 1000LL * 5000LL};
                KeDelayExecutionThread(KernelMode, FALSE, &wait);

                const auto mods = ::GetModules(pep, FALSE);
                for (const auto &mod : mods) {
                  if (mod.BaseDllName == targetModule) {
                    base = mod.DllBase;
                    break;
                  }
                }

                hunt_pid = reinterpret_cast<HANDLE>(SearchHuntProcess());
              }

              if (!hunt_pid) {
                LARGE_INTEGER wait = {.QuadPart =
                                          (-1LL) * 10LL * 1000LL * 5000LL};
                KeDelayExecutionThread(KernelMode, FALSE, &wait);
                ::CloseProcess(&pep, &obj);
                continue;
              }

#ifdef HUNT2_DEBUG
              logger.Write("%s\n", "PatternScanner");
              Memory memory(pep);
              // SysGlobEnvSig = "48 89 7C 24 ? E8 ? ? ? ? 48 8B 05 [? ? ? ?] 45 33 C0"
              {
                PatternScanner::ProcessModule scanner(
                  pep, obj, {0x48, 0x89, 0x7C, 0x24, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x45, 0x33, 0xC0},
                  skCrypt("xxxx?x????xxx????xxx"));
                PatternScanner::ResultVec results;
                auto found = scanner.Scan(targetModule, results);
                if (!found)
                  logger.Write("%s\n",
                               "(SysGEnv) Pattern Scan not found or failed!");
                for (const auto result : results) {
                  const auto sysgenv = memory.Read<uint64_t>(result.BaseAddress + result.Offset + 13);
                  logger.Write("(SysGEnv) Pattern Offset: %zu (Base + Offset: 0x%X) --> 0x%X\n",
                               result.Offset, result.BaseAddress + result.Offset, sysgenv);
                }
              }
              // NoSway = "48 89 83 ? ? ? ? 48 8B 45 ? 48 89 83 ? ? ? ? 48 8b ? ? [48 89 83 ? ? ? ?]"
              {
                PatternScanner::ProcessModule scanner(
                  pep, obj, {0x48, 0x89, 0x83, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x45, 0x00, 0x48, 0x89, 0x83, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x00, 0x00, 0x48, 0x89, 0x83, 0x00, 0x00, 0x00, 0x00},
                  skCrypt("xxx????xxx?xxx????xx??xxx????"));
                PatternScanner::ResultVec results;
                auto found = scanner.Scan(targetModule, results);
                if (!found)
                  logger.Write("%s\n",
                               "(NoSway) Pattern Scan not found or failed!");
                for (const auto result : results) {
                  logger.Write("(NoSway) Pattern Offset: %zu (Base + Offset: 0x%X)\n",
                               result.Offset, result.BaseAddress + result.Offset);
                  uint8_t nop[7] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
                  memory.Write(result.BaseAddress + result.Offset + 22, nop);
                }
              }
#endif
            }

        // Offsets stolen from:
        // https://www.unknowncheats.me/forum/other-fps-games/350352-hunt-showdown-51.html
#ifdef HUNT2_DEBUG
            cur_iter++;
#endif

            Memory memory(pep);
            auto sys_global_env = memory.Read<uint64_t>(base + 0x2827328);

            auto entity_system = memory.Read<uint64_t>(sys_global_env + 0xC0);
            auto number_of_objects =
                memory.Read<uint16_t>(entity_system + 0x40092);
            uint64_t entity_list = entity_system + 0x40078;

            for (decltype(number_of_objects) i = 0; i < number_of_objects;
                 ++i) {
              auto entity =
                  memory.Read<uint64_t>(entity_list + i * sizeof(uint64_t));
              if (!entity)
                continue;

              auto entity_name_ptr = memory.ReadChain<uint64_t>(entity, { 0x18, 0x10 });
              char entity_name[128] = {};
              memory.ReadString<sizeof(entity_name)>(entity_name_ptr,
                                                     entity_name);
#ifdef HUNT2_DEBUG
              objects_found[entity_name]++;
#endif

              if (STRNCMP_CR(entity_name, "ShootingRange_Target") == 0 ||
                  STRNCMP_CR(entity_name, "HunterBasic") == 0 ||
                  STRNCMP_CR(entity_name, "Hunter") == 0) {
                uint64_t color = 0x0004ffaf;
                auto slots_ptr = memory.Read<uint64_t>(entity + 0xA8);
                auto slot_ptr = memory.Read<uint64_t>(slots_ptr + 0);
                auto render_node_ptr = memory.Read<uint64_t>(slot_ptr + 0xA0);

                memory.Write<uint32_t>(render_node_ptr + 0x10, 0x80018);
                memory.Write<float>(render_node_ptr + 0x2c, 10000.f);
                memory.Write<decltype(color)>(render_node_ptr + 0x130, color);
#ifdef HUNT2_DEBUG
                render_nodes_found[render_node_ptr]++;
#endif
              } else if (STRNCMP_CR(entity_name, "boss") == 0 ||
                         STRNCMP_CR(entity_name, "target") == 0 ||
                         STRNCMP_CR(entity_name, "spider") == 0 ||
                         STRNCMP_CR(entity_name, "grunts.specials") == 0 ||
                         STRNCMP_CR(entity_name, "butcher") == 0 ||
                         STRNCMP_CR(entity_name, "immolater") == 0 ||
                         STRNCMP_CR(entity_name, "ammoswapbox") == 0) {
                auto slots_ptr = memory.Read<uint64_t>(entity + 0xA8);
                auto slot_ptr = memory.Read<uint64_t>(slots_ptr + 0);
                auto render_node_ptr = memory.Read<uint64_t>(slot_ptr + 0xA0);

                memory.Write<uint32_t>(render_node_ptr + 0x10, 0x80018);
                memory.Write<float>(render_node_ptr + 0x2c, 10000.f);
                memory.Write<uint64_t>(render_node_ptr + 0x130, 0x0004ff00);
              }
            }
#ifdef HUNT2_DEBUG
            if ((cur_iter % print_every) == 0) {
              logger.Write("[DBG #{}][Cur Objects: {}]\n", cur_iter, number_of_objects);
              for (const auto &object : objects_found)
                logger.Write("Object `{}' found: {} times\n", object.first,
                             object.second);
              for (const auto &render_node : render_nodes_found)
                logger.Write("Render Node {} found: {} times\n",
                         render_node.first, render_node.second);

              objects_found.clear();
              render_nodes_found.clear();
            }
#endif
          }
          if (hunt_pid)
            ::CloseProcess(&pep, &obj);
#ifdef HUNT2_DEBUG
          logger.Write("Done.\n");
#endif
        }
        __dppexcept(mainloop_seh) { return STATUS_UNSUCCESSFUL; }
        __dpptryend(mainloop_seh);

        return STATUS_SUCCESS;
      },
      nullptr);

  return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ struct _DRIVER_OBJECT *DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);
  DbgPrint("%s\n", "Waiting for thread termination..");
  __dpptry(unload_exception_handler, unload_seh) {
    shutdown_event.Notify();
    while (thread.WaitForTermination() != STATUS_UNSUCCESSFUL) {
    }
  }
  __dppexcept(unload_seh) {}
  __dpptryend(unload_seh);
}
}
