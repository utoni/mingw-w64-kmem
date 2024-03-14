#include <ntddk.h>

#include <EASTL/array.h>
#include <DriverThread.hpp>
#include <obfuscate.hpp>

#include "memory.hpp"

using namespace DriverThread;

static Thread thread;
static Event shutdown_event;
static auto targetProcess = skCrypt(L"EscapeFromTarkov.exe");
static auto targetModule = skCrypt(L"UnityPlayer.dll");

struct BaseObject
{
    uint64_t previousObjectLink;
    uint64_t nextObjectLink;
    uint64_t object;
};

struct GameObjectManager
{
    uint64_t lastTaggedObject;
    uint64_t taggedObjects;
    uint64_t lastActiveObject;
    uint64_t activeObjects;
    uint64_t LastActiveNode;
    uint64_t ActiveNodes;
};

struct UnityList
{
    char pad[16]; // 0x00->0x10;
    uint64_t pointer;
    uint32_t size;
};

static uint64_t GetObjectFromList(Memory& memory, uint64_t listPtr, uint64_t lastObjectPtr, const char * const objectName)
{
    char name[128];
    uint64_t classNamePtr = 0x0;

    BaseObject activeObject = memory.Read<BaseObject>(listPtr);
    BaseObject lastObject = memory.Read<BaseObject>(lastObjectPtr);

    if (activeObject.object != 0x0)
    {
        while (activeObject.object != 0 && activeObject.object != lastObject.object)
        {
            classNamePtr = memory.Read<uint64_t>(activeObject.object + 0x60);
            memory.ReadBuffer<char, sizeof(name)>(classNamePtr, name);

            if (strncmp(name, objectName, sizeof(name)) == 0)
                return activeObject.object;

            activeObject = memory.Read<BaseObject>(activeObject.nextObjectLink);
        }
    }
    if (lastObject.object != 0x0)
    {
        classNamePtr = memory.Read<uint64_t>(lastObject.object + 0x60);
        memory.ReadBuffer<char, sizeof(name)>(classNamePtr, name);

        if (strncmp(name, objectName, sizeof(name)) == 0)
            return lastObject.object;
    }

    memset(name, 0, sizeof(name));

    return 0;
}

static uint64_t SearchTarkovProcess(void) {
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

NTSTATUS DriverEntry(_In_ struct _DRIVER_OBJECT *DriverObject,
                     _In_ PUNICODE_STRING RegistryPath) {
  UNREFERENCED_PARAMETER(DriverObject);
  UNREFERENCED_PARAMETER(RegistryPath);

  auto args = eastl::make_shared<ThreadArgs>();
  thread.Start(
      [](eastl::shared_ptr<ThreadArgs> args) {
        UNREFERENCED_PARAMETER(args);

        HANDLE tarkov_pid = NULL;
        PEPROCESS pep = NULL;
        HANDLE obj = NULL;
        uint64_t base = 0;
        LONGLONG wait_timeout = (-1LL) * 10LL * 1000LL * 250LL;

        DbgPrint("%s\n", "start");
        while (shutdown_event.Wait(wait_timeout) == STATUS_TIMEOUT) {
          if (!tarkov_pid) {
            wait_timeout = (-1LL) * 10LL * 1000LL * 1000LL;
            tarkov_pid = reinterpret_cast<HANDLE>(SearchTarkovProcess());
            if (tarkov_pid == NULL) {
              continue;
            }
            DbgPrint("pid: %p\n", tarkov_pid);

            if (!NT_SUCCESS(::OpenProcess(tarkov_pid, &pep, &obj))) {
              tarkov_pid = NULL;
              continue;
            }

            base = 0;
            while (!base && tarkov_pid) {
              LARGE_INTEGER wait = {.QuadPart = (-1LL) * 10LL * 1000LL * 250LL};
              KeDelayExecutionThread(KernelMode, TRUE, &wait);

              const auto mods = ::GetModules(pep, FALSE);
              DbgPrint("mods: %zu\n", mods.size());
              for (const auto &mod : mods) {
                if (mod.BaseDllName == targetModule) {
                  DbgPrint("%s\n", "found");
                  base = mod.DllBase;
                  break;
                }
              }

              tarkov_pid = reinterpret_cast<HANDLE>(SearchTarkovProcess());
            }

            if (!tarkov_pid) {
              ::CloseProcess(&pep, &obj);
              continue;
            }

            //wait_timeout = (-1LL) * 10LL * 1000LL * 50LL;
          }

          Memory memory(pep);
          auto gom_ptr = memory.Read<uint64_t>(base + 0x17FFD28);
          auto gom = memory.Read<GameObjectManager>(gom_ptr);
          if (!gom_ptr) {
            ::CloseProcess(&pep, &obj);
            tarkov_pid = NULL;
            continue;
          }

          uint64_t activeNodes = memory.Read<uint64_t>(gom.ActiveNodes);
          uint64_t lastActiveNode = memory.Read<uint64_t>(gom.LastActiveNode);
          auto game_world = GetObjectFromList(memory, activeNodes, lastActiveNode, "GameWorld");
          auto local_game_world = memory.ReadChain<uint64_t>(game_world, { 0x30, 0x18, 0x28 });
          auto local_player = memory.Read<uint64_t>(local_game_world + 0x118);
          auto player_list_ptr = memory.Read<uint64_t>(local_game_world + 0xC0);
          auto player_list = memory.Read<UnityList>(player_list_ptr);
          auto count = memory.Read<uint32_t>(player_list_ptr + 0x40);

          //auto registered_players = memory.Read<uint64_t>(local_game_world + 0xC0);
          //auto player_count = memory.Read<uint32_t>(registered_players + 0x18);
          DbgPrint("%p,%p,%p,%p,%p,%u,%u\n", game_world, local_game_world, local_player, player_list_ptr, player_list.pointer, player_list.size, count);
#if 0
          auto lgw = memory.ReadChain<uint64_t>(gom, { 0x30, 0x18, 0x28 });
          if (!lgw)
            continue;

          auto registered_players = memory.Read<uint64_t>(lgw + 0xC0);
          auto player_count = memory.Read<uint64_t>(registered_players + 0x18);
          uint64_t i;
          for (i = 0; i < player_count; ++i) {
            auto player_ptr = memory.Read<uint64_t>(registered_players + 0x20 + i * 0x8);
            auto class_name_ptr = memory.ReadChain<uint64_t>(player_ptr, { 0x0, 0x0, 0x48 });
            //if (!class_name_ptr)
            //  break;
            char buf[64];
            memory.ReadBuffer<char, 64>(class_name_ptr, buf);
            DbgPrint("++%.*s++\n", (int)memory.LastSize(), buf);
          }
          DbgPrint("__%llu,%llu__\n", i, player_count);
#endif
#if 0
          auto camera_address = memory.Read<uint64_t>(base + 0x0179F500);
          if (!camera_address)
            continue;
          auto all_cameras = memory.Read<uint64_t>(camera_address);
          if (!all_cameras)
            continue;

          uint64_t optic_camera = 0;
          for (uint64_t i = 0; i < 512; ++i) {
            auto camera = memory.Read<uint64_t>(all_cameras + i * 0x8);
            if (!camera)
              break;
            auto camera_obj = memory.Read<uint64_t>(camera + 0x30);
            if (!camera_obj)
              break;
            auto camera_name_ptr = memory.Read<uint64_t>(camera_obj + 0x60);

            char buf[64];
            memory.ReadBuffer<char, 64>(camera_name_ptr, buf);
            if (memory.LastSize() > 0 && strncmp(buf, skCrypt("BaseOpticCamera(Clone)"), sizeof(buf)) == 0)
              optic_camera = camera_name_ptr;
          }
          DbgPrint("--%p,%p--\n", lgw, optic_camera);

          if (!optic_camera)
            continue;
          auto component_list = memory.Read<uint64_t>(optic_camera + 0x30);
          if (!component_list)
            continue;
          uint64_t i;
          for (i = 0; i < 64; ++i) {
            auto field = memory.ReadChain<uint64_t>(component_list, { 0x8 + (i * 0x10), 0x28 });
            if (!field)
              break;
          }
          DbgPrint("++%llu++\n", i);
#endif
        }

        return STATUS_SUCCESS;
      },
      args);

  return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ struct _DRIVER_OBJECT *DriverObject) {
  UNREFERENCED_PARAMETER(DriverObject);

  DbgPrint("%s\n", "Waiting for thread termination..");
  shutdown_event.Notify();
  thread.WaitForTermination();
}
}
