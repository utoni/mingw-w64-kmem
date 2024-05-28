#ifndef NATIVE_H
#define NATIVE_H 1

#define MM_COPY_MEMORY_PHYSICAL             0x1
#define MM_COPY_MEMORY_VIRTUAL              0x2

// QuerySystemInformation

typedef enum _SYSTEM_INFORMATION_CLASS {
  SystemBasicInformation = 0x0,
  SystemProcessInformation = 0x5
} SYSTEM_INFORMATION_CLASS;

typedef enum _MEMORY_INFORMATION_CLASS {
  MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_BASIC_INFORMATION {
  PVOID BaseAddress;
  PVOID AllocationBase;
  ULONG AllocationProtect;
  SIZE_T RegionSize;
  ULONG State;
  ULONG Protect;
  ULONG Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION {
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER CreateTime;
  ULONG WaitTime;
  PVOID StartAddress;
  CLIENT_ID ClientId;
  KPRIORITY Priority;
  KPRIORITY BasePriority;
  ULONG ContextSwitchCount;
  LONG State;
  LONG WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
  ULONG NextEntryDelta;
  ULONG ThreadCount;
  ULONG Reserved1[6];
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ProcessName;
  KPRIORITY BasePriority;
  SIZE_T ProcessId;
  SIZE_T InheritedFromProcessId;
  ULONG HandleCount;
  ULONG Reserved2[2];
  VM_COUNTERS VmCounters;
  IO_COUNTERS IoCounters;
  SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

// Modules

typedef struct _KLDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  PVOID ExceptionTable;
  ULONG ExceptionTableSize;
  PVOID GpValue;
  PVOID NonPagedDebugInfo;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  USHORT LoadCount;
  USHORT __Unused;
  PVOID SectionPointer;
  ULONG CheckSum;
  PVOID LoadedImports;
  PVOID PatchInformation;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA32 {
  ULONG Length;
  UCHAR Initialized;
  ULONG SsHandle;
  LIST_ENTRY32 InLoadOrderModuleList;
  LIST_ENTRY32 InMemoryOrderModuleList;
  LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, *PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
  LIST_ENTRY32 InLoadOrderLinks;
  LIST_ENTRY32 InMemoryOrderLinks;
  LIST_ENTRY32 InInitializationOrderLinks;
  ULONG DllBase;
  ULONG EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING32 FullDllName;
  UNICODE_STRING32 BaseDllName;
  ULONG Flags;
  USHORT LoadCount;
  USHORT TlsIndex;
  LIST_ENTRY32 HashLinks;
  ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB32 {
  UCHAR InheritedAddressSpace;
  UCHAR ReadImageFileExecOptions;
  UCHAR BeingDebugged;
  UCHAR BitField;
  ULONG Mutant;
  ULONG ImageBaseAddress;
  ULONG Ldr;
  ULONG ProcessParameters;
  ULONG SubSystemData;
  ULONG ProcessHeap;
  ULONG FastPebLock;
  ULONG AtlThunkSListPtr;
  ULONG IFEOKey;
  ULONG CrossProcessFlags;
  ULONG UserSharedInfoPtr;
  ULONG SystemReserved;
  ULONG AtlThunkSListPtr32;
  ULONG ApiSetMap;
} PEB32, *PPEB32;

typedef struct _PEB_LDR_DATA {
  ULONG Length;
  UCHAR Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  USHORT LoadCount;
  USHORT TlsIndex;
  LIST_ENTRY HashLinks;
  ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
  UCHAR InheritedAddressSpace;
  UCHAR ReadImageFileExecOptions;
  UCHAR BeingDebugged;
  UCHAR BitField;
  PVOID Mutant;
  PVOID ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
  PVOID ProcessParameters;
  PVOID SubSystemData;
  PVOID ProcessHeap;
  PVOID FastPebLock;
  PVOID AtlThunkSListPtr;
  PVOID IFEOKey;
  PVOID CrossProcessFlags;
  PVOID KernelCallbackTable;
  ULONG SystemReserved;
  ULONG AtlThunkSListPtr32;
  PVOID ApiSetMap;
} PEB, *PPEB;

typedef struct _MM_COPY_ADDRESS {
  union {
    PVOID            VirtualAddress;
    PHYSICAL_ADDRESS PhysicalAddress;
  };
} MM_COPY_ADDRESS, *PMMCOPY_ADDRESS;

#endif
