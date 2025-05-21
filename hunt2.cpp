/*
 * Won't work after CryEngine 5.11 update (2024-08-15)
 */
#include <ntddk.h>

#include <EASTL/array.h>
#include <EASTL/unordered_map.h>
#include <eastl_compat.hpp>
#include <except.h>
#include <DriverThread.hpp>
#include <obfuscate.hpp>

#include "memory.hpp"
#include "stringify.hpp"

#define STRNCMP_CR(haystack, needle) \
    (strncmp(haystack, skCrypt(needle), sizeof(needle) - 1))

using namespace DriverThread;

static Thread thread;
static Event shutdown_event;
static auto targetProcess = skCrypt(L"HuntGame.exe");
static auto targetModule = skCrypt(L"GameHunt.dll");

enum ColorType : uint32_t {
  Pink = 0xFFA0FFFF,
  Red = 0xFF000080,
  Green = 0x00FF00FF,
  Blue = 0x0000FF60,
  Cyan = 0x00FFFFFF,
  Orange = 0xFFA500FF,
  Yellow = 0xFFFF0060,
  White = 0xFFFFFFFF
};

static uint64_t SearchHuntProcess(void) {
  const auto &procs = ::GetProcesses();
  const auto &found = eastl::find_if(procs.begin(), procs.end(),
                                     [](const auto &item) {
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

int mainloop_exception_handler(_In_ EXCEPTION_POINTERS * lpEP)
{
    (void)lpEP;
    return EXCEPTION_EXECUTE_HANDLER;
}

NTSTATUS DriverEntry(_In_ struct _DRIVER_OBJECT *DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  auto args = eastl::make_shared<ThreadArgs>();
  thread.Start(
      [](eastl::shared_ptr<ThreadArgs> args) {
        UNREFERENCED_PARAMETER(args);

        HANDLE hunt_pid = NULL;
        PEPROCESS pep = NULL;
        HANDLE obj = NULL;
        uint64_t base = 0;
        LONGLONG wait_timeout = (-1LL) * 10LL * 1000LL * 250LL;

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

            if (!NT_SUCCESS(::OpenProcess(hunt_pid, &pep, &obj))) {
              hunt_pid = NULL;
              continue;
            }

            base = 0;
            while (!base && hunt_pid) {
              LARGE_INTEGER wait = {.QuadPart = (-1LL) * 10LL * 1000LL * 5000LL};
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
              LARGE_INTEGER wait = {.QuadPart = (-1LL) * 10LL * 1000LL * 5000LL};
              KeDelayExecutionThread(KernelMode, FALSE, &wait);
              ::CloseProcess(&pep, &obj);
              continue;
            }
          }

          // Offsets stolen from: https://www.unknowncheats.me/forum/other-fps-games/350352-hunt-showdown-51.html
          Memory memory(pep);
          auto sys_global_env = memory.Read<uint64_t>(base + 0x23582C0);

          auto entity_system = memory.Read<uint64_t>(sys_global_env + 0xC0);
          uint16_t number_of_objects = memory.Read<uint16_t>(entity_system + 0x40092);
          uint64_t entity_list = entity_system + 0x40098;

          for (decltype(number_of_objects) i = 0; i < number_of_objects; ++i) {
            auto entity = memory.Read<uint64_t>(entity_list + i * sizeof(uint64_t));
            if (!entity)
              continue;

            auto entity_name_ptr = memory.Read<uint64_t>(entity + 0x10);
            char entity_name[128] = {};
            memory.ReadString<sizeof(entity_name)>(entity_name_ptr, entity_name);

            if (STRNCMP_CR(entity_name, "ShootingRange_Target") == 0 ||
                STRNCMP_CR(entity_name, "HunterBasic") == 0)
            {
              auto slots_ptr = memory.Read<uint64_t>(entity + 0xA8);
              auto slot_ptr = memory.Read<uint64_t>(slots_ptr + 0);
              auto render_node_ptr = memory.Read<uint64_t>(slot_ptr + 0xA0);

              auto rgba_color = memory.Read<uint32_t>(render_node_ptr + 0x2C);
              if (rgba_color != ColorType::Cyan /* team */) {
                memory.Write<uint32_t>(render_node_ptr + 0x10, 0x80018);
                memory.Write<uint32_t>(render_node_ptr + 0x2C, ColorType::Pink);
              }
            } else if (STRNCMP_CR(entity_name, "Target_Butcher") == 0 ||
                       STRNCMP_CR(entity_name, "Target_Assassin") == 0 ||
                       STRNCMP_CR(entity_name, "Spider_target") == 0 ||
                       STRNCMP_CR(entity_name, "Target_Scrapbeak") == 0 ||
                       STRNCMP_CR(entity_name, "Grunts.specials") == 0 ||
                       STRNCMP_CR(entity_name, "immolator_el") == 0)
            {
                auto slots_ptr = memory.Read<uint64_t>(entity + 0xA8);
                auto slot_ptr = memory.Read<uint64_t>(slots_ptr + 0);
                auto render_node_ptr = memory.Read<uint64_t>(slot_ptr + 0xA0);

                memory.Write<uint32_t>(render_node_ptr + 0x10, 0x80018);
                memory.Write<uint32_t>(render_node_ptr + 0x2C, ColorType::Red);
            } else if (STRNCMP_CR(entity_name, "currency_collection") == 0 ||
                       STRNCMP_CR(entity_name, "cash_register") == 0 ||
                       STRNCMP_CR(entity_name, "cash") == 0)
            {
                auto slots_ptr = memory.Read<uint64_t>(entity + 0xA8);
                auto slot_ptr = memory.Read<uint64_t>(slots_ptr + 0);
                auto render_node_ptr = memory.Read<uint64_t>(slot_ptr + 0xA0);

                memory.Write<uint32_t>(render_node_ptr + 0x10, 0x80018);
                memory.Write<uint32_t>(render_node_ptr + 0x2C, ColorType::Yellow);
            } else if (STRNCMP_CR(entity_name, "TraitCharm") == 0)
            {
                auto slots_ptr = memory.Read<uint64_t>(entity + 0xA8);
                auto slot_ptr = memory.Read<uint64_t>(slots_ptr + 0);
                auto render_node_ptr = memory.Read<uint64_t>(slot_ptr + 0xA0);

                memory.Write<uint32_t>(render_node_ptr + 0x10, 0x80018);
                memory.Write<uint32_t>(render_node_ptr + 0x2C, ColorType::Blue);
            }
          }
        }
        } __dppexcept(mainloop_seh) {
            return STATUS_UNSUCCESSFUL;
        } __dpptryend(mainloop_seh);

        return STATUS_SUCCESS;
      },
      args);

  return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ struct _DRIVER_OBJECT *DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  DbgPrint("%s\n", "Waiting for thread termination..");
  __dpptry(mainloop_exception_handler, unload_seh)
  {
    shutdown_event.Notify();
    thread.WaitForTermination();
  } __dppexcept(unload_seh) {
  } __dpptryend(unload_seh);
}
}
