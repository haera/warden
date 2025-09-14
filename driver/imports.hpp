#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>

#define ImageFileName 0x5A8 // EPROCESS::ImageFileName
#define ActiveThreads 0x5F0 // EPROCESS::ActiveThreads
#define ThreadListHead 0x5E0 // EPROCESS::ThreadListHead
#define ActiveProcessLinks 0x448 // EPROCESS::ActiveProcessLinks

#define DebugPrint(...) DbgPrintEx( DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, "?" __VA_ARGS__ )

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS,
* PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void);

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;


typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

//0x28 bytes (sizeof)
struct _ACTIVATION_CONTEXT_STACK
{
	struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* ActiveFrame;                //0x0
	struct _LIST_ENTRY FrameListCache;                                      //0x8
	ULONG Flags;                                                            //0x18
	ULONG NextCookieSequenceNumber;                                         //0x1c
	ULONG StackId;                                                          //0x20
};

//0x4e8 bytes (sizeof)
struct _GDI_TEB_BATCH
{
	ULONG Offset : 31;                                                        //0x0
	ULONG HasRenderingCommand : 1;                                            //0x0
	ULONGLONG HDC;                                                          //0x8
	ULONG Buffer[310];                                                      //0x10
};

/*
//0x1838 bytes (sizeof)
struct _TEB
{
	struct _NT_TIB NtTib;                                                   //0x0
	VOID* EnvironmentPointer;                                               //0x38
	struct _CLIENT_ID ClientId;                                             //0x40
	VOID* ActiveRpcHandle;                                                  //0x50
	VOID* ThreadLocalStoragePointer;                                        //0x58
	struct _PEB* ProcessEnvironmentBlock;                                   //0x60
	ULONG LastErrorValue;                                                   //0x68
	ULONG CountOfOwnedCriticalSections;                                     //0x6c
	VOID* CsrClientThread;                                                  //0x70
	VOID* Win32ThreadInfo;                                                  //0x78
	ULONG User32Reserved[26];                                               //0x80
	ULONG UserReserved[5];                                                  //0xe8
	VOID* WOW32Reserved;                                                    //0x100
	ULONG CurrentLocale;                                                    //0x108
	ULONG FpSoftwareStatusRegister;                                         //0x10c
	VOID* ReservedForDebuggerInstrumentation[16];                           //0x110
	VOID* SystemReserved1[30];                                              //0x190
	CHAR PlaceholderCompatibilityMode;                                      //0x280
	UCHAR PlaceholderHydrationAlwaysExplicit;                               //0x281
	CHAR PlaceholderReserved[10];                                           //0x282
	ULONG ProxiedProcessId;                                                 //0x28c
	struct _ACTIVATION_CONTEXT_STACK _ActivationStack;                      //0x290
	UCHAR WorkingOnBehalfTicket[8];                                         //0x2b8
	LONG ExceptionCode;                                                     //0x2c0
	UCHAR Padding0[4];                                                      //0x2c4
	struct _ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;        //0x2c8
	ULONGLONG InstrumentationCallbackSp;                                    //0x2d0
	ULONGLONG InstrumentationCallbackPreviousPc;                            //0x2d8
	ULONGLONG InstrumentationCallbackPreviousSp;                            //0x2e0
	ULONG TxFsContext;                                                      //0x2e8
	UCHAR InstrumentationCallbackDisabled;                                  //0x2ec
	UCHAR UnalignedLoadStoreExceptions;                                     //0x2ed
	UCHAR Padding1[2];                                                      //0x2ee
	struct _GDI_TEB_BATCH GdiTebBatch;                                      //0x2f0
	struct _CLIENT_ID RealClientId;                                         //0x7d8
	VOID* GdiCachedProcessHandle;                                           //0x7e8
	ULONG GdiClientPID;                                                     //0x7f0
	ULONG GdiClientTID;                                                     //0x7f4
	VOID* GdiThreadLocalInfo;                                               //0x7f8
	ULONGLONG Win32ClientInfo[62];                                          //0x800 holds info about HWND/WND
	VOID* glDispatchTable[233];                                             //0x9f0
	ULONGLONG glReserved1[29];                                              //0x1138
	VOID* glReserved2;                                                      //0x1220
	VOID* glSectionInfo;                                                    //0x1228
	VOID* glSection;                                                        //0x1230
	VOID* glTable;                                                          //0x1238
	VOID* glCurrentRC;                                                      //0x1240
	VOID* glContext;                                                        //0x1248
	ULONG LastStatusValue;                                                  //0x1250
	UCHAR Padding2[4];                                                      //0x1254
	struct _UNICODE_STRING StaticUnicodeString;                             //0x1258
	WCHAR StaticUnicodeBuffer[261];                                         //0x1268
	UCHAR Padding3[6];                                                      //0x1472
	VOID* DeallocationStack;                                                //0x1478
	VOID* TlsSlots[64];                                                     //0x1480
	struct _LIST_ENTRY TlsLinks;                                            //0x1680
	VOID* Vdm;                                                              //0x1690
	VOID* ReservedForNtRpc;                                                 //0x1698
	VOID* DbgSsReserved[2];                                                 //0x16a0
	ULONG HardErrorMode;                                                    //0x16b0
	UCHAR Padding4[4];                                                      //0x16b4
	VOID* Instrumentation[11];                                              //0x16b8
	struct _GUID ActivityId;                                                //0x1710
	VOID* SubProcessTag;                                                    //0x1720
	VOID* PerflibData;                                                      //0x1728
	VOID* EtwTraceData;                                                     //0x1730
	VOID* WinSockData;                                                      //0x1738
	ULONG GdiBatchCount;                                                    //0x1740
	union
	{
		struct _PROCESSOR_NUMBER CurrentIdealProcessor;                     //0x1744
		ULONG IdealProcessorValue;                                          //0x1744
		struct
		{
			UCHAR ReservedPad0;                                             //0x1744
			UCHAR ReservedPad1;                                             //0x1745
			UCHAR ReservedPad2;                                             //0x1746
			UCHAR IdealProcessor;                                           //0x1747
		};
	};
	ULONG GuaranteedStackBytes;                                             //0x1748
	UCHAR Padding5[4];                                                      //0x174c
	VOID* ReservedForPerf;                                                  //0x1750
	VOID* ReservedForOle;                                                   //0x1758
	ULONG WaitingOnLoaderLock;                                              //0x1760
	UCHAR Padding6[4];                                                      //0x1764
	VOID* SavedPriorityState;                                               //0x1768
	ULONGLONG ReservedForCodeCoverage;                                      //0x1770
	VOID* ThreadPoolData;                                                   //0x1778
	VOID** TlsExpansionSlots;                                               //0x1780
	VOID* DeallocationBStore;                                               //0x1788
	VOID* BStoreLimit;                                                      //0x1790
	ULONG MuiGeneration;                                                    //0x1798
	ULONG IsImpersonating;                                                  //0x179c
	VOID* NlsCache;                                                         //0x17a0
	VOID* pShimData;                                                        //0x17a8
	ULONG HeapData;                                                         //0x17b0
	UCHAR Padding7[4];                                                      //0x17b4
	VOID* CurrentTransactionHandle;                                         //0x17b8
	struct _TEB_ACTIVE_FRAME* ActiveFrame;                                  //0x17c0
	VOID* FlsData;                                                          //0x17c8
	VOID* PreferredLanguages;                                               //0x17d0
	VOID* UserPrefLanguages;                                                //0x17d8
	VOID* MergedPrefLanguages;                                              //0x17e0
	ULONG MuiImpersonation;                                                 //0x17e8
	union
	{
		volatile USHORT CrossTebFlags;                                      //0x17ec
		USHORT SpareCrossTebBits : 16;                                        //0x17ec
	};
	union
	{
		USHORT SameTebFlags;                                                //0x17ee
		struct
		{
			USHORT SafeThunkCall : 1;                                         //0x17ee
			USHORT InDebugPrint : 1;                                          //0x17ee
			USHORT HasFiberData : 1;                                          //0x17ee
			USHORT SkipThreadAttach : 1;                                      //0x17ee
			USHORT WerInShipAssertCode : 1;                                   //0x17ee
			USHORT RanProcessInit : 1;                                        //0x17ee
			USHORT ClonedThread : 1;                                          //0x17ee
			USHORT SuppressDebugMsg : 1;                                      //0x17ee
			USHORT DisableUserStackWalk : 1;                                  //0x17ee
			USHORT RtlExceptionAttached : 1;                                  //0x17ee
			USHORT InitialThread : 1;                                         //0x17ee
			USHORT SessionAware : 1;                                          //0x17ee
			USHORT LoadOwner : 1;                                             //0x17ee
			USHORT LoaderWorker : 1;                                          //0x17ee
			USHORT SkipLoaderInit : 1;                                        //0x17ee
			USHORT SpareSameTebBits : 1;                                      //0x17ee
		};
	};
	VOID* TxnScopeEnterCallback;                                            //0x17f0
	VOID* TxnScopeExitCallback;                                             //0x17f8
	VOID* TxnScopeContext;                                                  //0x1800
	ULONG LockCount;                                                        //0x1808
	LONG WowTebOffset;                                                      //0x180c
	VOID* ResourceRetValue;                                                 //0x1810
	VOID* ReservedForWdf;                                                   //0x1818
	ULONGLONG ReservedForCrt;                                               //0x1820
	struct _GUID EffectiveContainerId;                                      //0x1828
};
*/

extern "C" __declspec(dllimport)
NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID * BaseAddress, PULONG ProtectSize, ULONG NewProtect, PULONG OldProtect);

extern "C" NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineNam);

extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

extern "C" NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);

extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

typedef struct _MEMORY_STRUCT
{
	BYTE type;
	LONG usermode_pid;
	LONG target_pid;
	const char* module_name;
	ULONG64 base_address;
	void* address;
	LONG size;
	void* output;
	ULONG magic;
}MEMORY_STRUCT;
