#pragma once

#include <ntifs.h>

#pragma pack(4)
typedef struct _PEB32
{
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
} PEB32, * PPEB32;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
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
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

struct _GDI_TEB_BATCH32
{
	ULONG Offset;                                                           //0x0
	ULONG HDC;                                                              //0x4
	ULONG Buffer[310];                                                      //0x8
};

struct _CLIENT_ID32
{
	ULONG UniqueProcess;                                                    //0x0
	ULONG UniqueThread;                                                     //0x4
};

typedef struct _TEB32
{
	struct _NT_TIB32 NtTib;                                                 //0x0
	ULONG EnvironmentPointer;                                               //0x1c
	struct _CLIENT_ID32 ClientId;                                           //0x20
	ULONG ActiveRpcHandle;                                                  //0x28
	ULONG ThreadLocalStoragePointer;                                        //0x2c
	ULONG ProcessEnvironmentBlock;                                          //0x30
	ULONG LastErrorValue;                                                   //0x34
	ULONG CountOfOwnedCriticalSections;                                     //0x38
	ULONG CsrClientThread;                                                  //0x3c
	ULONG Win32ThreadInfo;                                                  //0x40
	ULONG User32Reserved[26];                                               //0x44
	ULONG UserReserved[5];                                                  //0xac
	ULONG WOW32Reserved;                                                    //0xc0
	ULONG CurrentLocale;                                                    //0xc4
	ULONG FpSoftwareStatusRegister;                                         //0xc8
	ULONG SystemReserved1[54];                                              //0xcc
	LONG ExceptionCode;                                                     //0x1a4
	ULONG ActivationContextStackPointer;                                    //0x1a8
	UCHAR SpareBytes[36];                                                   //0x1ac
	ULONG TxFsContext;                                                      //0x1d0
	struct _GDI_TEB_BATCH32 GdiTebBatch;                                    //0x1d4
	struct _CLIENT_ID32 RealClientId;                                       //0x6b4
	ULONG GdiCachedProcessHandle;                                           //0x6bc
	ULONG GdiClientPID;                                                     //0x6c0
	ULONG GdiClientTID;                                                     //0x6c4
	ULONG GdiThreadLocalInfo;                                               //0x6c8
	ULONG Win32ClientInfo[62];                                              //0x6cc
	ULONG glDispatchTable[233];                                             //0x7c4
	ULONG glReserved1[29];                                                  //0xb68
	ULONG glReserved2;                                                      //0xbdc
	ULONG glSectionInfo;                                                    //0xbe0
	ULONG glSection;                                                        //0xbe4
	ULONG glTable;                                                          //0xbe8
	ULONG glCurrentRC;                                                      //0xbec
	ULONG glContext;                                                        //0xbf0
	ULONG LastStatusValue;                                                  //0xbf4
	struct _STRING32 StaticUnicodeString;                                   //0xbf8
	WCHAR StaticUnicodeBuffer[261];                                         //0xc00
	ULONG DeallocationStack;                                                //0xe0c
	ULONG TlsSlots[64];                                                     //0xe10
	struct LIST_ENTRY32 TlsLinks;                                           //0xf10
	ULONG Vdm;                                                              //0xf18
	ULONG ReservedForNtRpc;                                                 //0xf1c
	ULONG DbgSsReserved[2];                                                 //0xf20
	ULONG HardErrorMode;                                                    //0xf28
	ULONG Instrumentation[9];                                               //0xf2c
	struct _GUID ActivityId;                                                //0xf50
	ULONG SubProcessTag;                                                    //0xf60
	ULONG EtwLocalData;                                                     //0xf64
	ULONG EtwTraceData;                                                     //0xf68
	ULONG WinSockData;                                                      //0xf6c
	ULONG GdiBatchCount;                                                    //0xf70
	union
	{
		struct _PROCESSOR_NUMBER CurrentIdealProcessor;                     //0xf74
		ULONG IdealProcessorValue;                                          //0xf74
		struct
		{
			UCHAR ReservedPad0;                                             //0xf74
			UCHAR ReservedPad1;                                             //0xf75
			UCHAR ReservedPad2;                                             //0xf76
			UCHAR IdealProcessor;                                           //0xf77
		};
	};
	ULONG GuaranteedStackBytes;                                             //0xf78
	ULONG ReservedForPerf;                                                  //0xf7c
	ULONG ReservedForOle;                                                   //0xf80
	ULONG WaitingOnLoaderLock;                                              //0xf84
	ULONG SavedPriorityState;                                               //0xf88
	ULONG SoftPatchPtr1;                                                    //0xf8c
	ULONG ThreadPoolData;                                                   //0xf90
	ULONG TlsExpansionSlots;                                                //0xf94
	ULONG MuiGeneration;                                                    //0xf98
	ULONG IsImpersonating;                                                  //0xf9c
	ULONG NlsCache;                                                         //0xfa0
	ULONG pShimData;                                                        //0xfa4
	ULONG HeapVirtualAffinity;                                              //0xfa8
	ULONG CurrentTransactionHandle;                                         //0xfac
	ULONG ActiveFrame;                                                      //0xfb0
	ULONG FlsData;                                                          //0xfb4
	ULONG PreferredLanguages;                                               //0xfb8
	ULONG UserPrefLanguages;                                                //0xfbc
	ULONG MergedPrefLanguages;                                              //0xfc0
	ULONG MuiImpersonation;                                                 //0xfc4
	union
	{
		volatile USHORT CrossTebFlags;                                      //0xfc8
		USHORT SpareCrossTebBits : 16;                                        //0xfc8
	};
	union
	{
		USHORT SameTebFlags;                                                //0xfca
		struct
		{
			USHORT SafeThunkCall : 1;                                         //0xfca
			USHORT InDebugPrint : 1;                                          //0xfca
			USHORT HasFiberData : 1;                                          //0xfca
			USHORT SkipThreadAttach : 1;                                      //0xfca
			USHORT WerInShipAssertCode : 1;                                   //0xfca
			USHORT RanProcessInit : 1;                                        //0xfca
			USHORT ClonedThread : 1;                                          //0xfca
			USHORT SuppressDebugMsg : 1;                                      //0xfca
			USHORT DisableUserStackWalk : 1;                                  //0xfca
			USHORT RtlExceptionAttached : 1;                                  //0xfca
			USHORT InitialThread : 1;                                         //0xfca
			USHORT SpareSameTebBits : 5;                                      //0xfca
		};
	};
	ULONG TxnScopeEnterCallback;                                            //0xfcc
	ULONG TxnScopeExitCallback;                                             //0xfd0
	ULONG TxnScopeContext;                                                  //0xfd4
	ULONG LockCount;                                                        //0xfd8
	ULONG SpareUlong0;                                                      //0xfdc
	ULONG ResourceRetValue;                                                 //0xfe0
}TEB32, * PTEB32;

#pragma pack()

typedef struct _LDR_DATA_TABLE_ENTRY
{
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	struct _UNICODE_STRING FullDllName;                                     //0x48
	struct _UNICODE_STRING BaseDllName;                                     //0x58
	ULONG Flags;                                                            //0x68
	USHORT LoadCount;                                                       //0x6c
	USHORT TlsIndex;                                                        //0x6e
	union
	{
		struct _LIST_ENTRY HashLinks;                                       //0x70
		struct
		{
			VOID* SectionPointer;                                           //0x70
			ULONG CheckSum;                                                 //0x78
		};
	};
	union
	{
		ULONG TimeDateStamp;                                                //0x80
		VOID* LoadedImports;                                                //0x80
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
	VOID* PatchInformation;                                                 //0x90
	struct _LIST_ENTRY ForwarderLinks;                                      //0x98
	struct _LIST_ENTRY ServiceTagLinks;                                     //0xa8
	struct _LIST_ENTRY StaticLinks;                                         //0xb8
	VOID* ContextInformation;                                               //0xc8
	ULONGLONG OriginalBase;                                                 //0xd0
	union _LARGE_INTEGER LoadTime;                                          //0xd8
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	VOID* SsHandle;                                                         //0x8
	struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
	struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
	struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
	VOID* EntryInProgress;                                                  //0x40
	UCHAR ShutdownInProgress;                                               //0x48
	VOID* ShutdownThreadId;                                                 //0x50
}PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _MPEB
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsLegacyProcess : 1;                                        //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR SpareBits : 3;                                              //0x3
		};
	};
	VOID* Mutant;                                                           //0x8
	VOID* ImageBaseAddress;                                                 //0x10
	struct _PEB_LDR_DATA* Ldr;                                              //0x18
	struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x20
	VOID* SubSystemData;                                                    //0x28
	VOID* ProcessHeap;                                                      //0x30
	struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
	VOID* AtlThunkSListPtr;                                                 //0x40
	VOID* IFEOKey;                                                          //0x48
	union
	{
		ULONG CrossProcessFlags;                                            //0x50
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x50
			ULONG ProcessInitializing : 1;                                    //0x50
			ULONG ProcessUsingVEH : 1;                                        //0x50
			ULONG ProcessUsingVCH : 1;                                        //0x50
			ULONG ProcessUsingFTH : 1;                                        //0x50
			ULONG ReservedBits0 : 27;                                         //0x50
		};
	};
	union
	{
		VOID* KernelCallbackTable;                                          //0x58
		VOID* UserSharedInfoPtr;                                            //0x58
	};
	ULONG SystemReserved[1];                                                //0x60
	ULONG AtlThunkSListPtr32;                                               //0x64
	VOID* ApiSetMap;                                                        //0x68
	ULONG TlsExpansionCounter;                                              //0x70
	VOID* TlsBitmap;                                                        //0x78
	ULONG TlsBitmapBits[2];                                                 //0x80
	VOID* ReadOnlySharedMemoryBase;                                         //0x88
	VOID* HotpatchInformation;                                              //0x90
	VOID** ReadOnlyStaticServerData;                                        //0x98
	VOID* AnsiCodePageData;                                                 //0xa0
	VOID* OemCodePageData;                                                  //0xa8
	VOID* UnicodeCaseTableData;                                             //0xb0
	ULONG NumberOfProcessors;                                               //0xb8
	ULONG NtGlobalFlag;                                                     //0xbc
	union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
	ULONGLONG HeapSegmentReserve;                                           //0xc8
	ULONGLONG HeapSegmentCommit;                                            //0xd0
	ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
	ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
	ULONG NumberOfHeaps;                                                    //0xe8
	ULONG MaximumNumberOfHeaps;                                             //0xec
	VOID** ProcessHeaps;                                                    //0xf0
	VOID* GdiSharedHandleTable;                                             //0xf8
	VOID* ProcessStarterHelper;                                             //0x100
	ULONG GdiDCAttributeList;                                               //0x108
	struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
	ULONG OSMajorVersion;                                                   //0x118
	ULONG OSMinorVersion;                                                   //0x11c
	USHORT OSBuildNumber;                                                   //0x120
	USHORT OSCSDVersion;                                                    //0x122
	ULONG OSPlatformId;                                                     //0x124
	ULONG ImageSubsystem;                                                   //0x128
	ULONG ImageSubsystemMajorVersion;                                       //0x12c
	ULONG ImageSubsystemMinorVersion;                                       //0x130
	ULONGLONG ActiveProcessAffinityMask;                                    //0x138
	ULONG GdiHandleBuffer[60];                                              //0x140
	VOID(*PostProcessInitRoutine)();                                       //0x230
	VOID* TlsExpansionBitmap;                                               //0x238
	ULONG TlsExpansionBitmapBits[32];                                       //0x240
	ULONG SessionId;                                                        //0x2c0
	union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
	union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
	VOID* pShimData;                                                        //0x2d8
	VOID* AppCompatInfo;                                                    //0x2e0
	struct _UNICODE_STRING CSDVersion;                                      //0x2e8
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
	ULONGLONG MinimumStackCommit;                                           //0x318
	struct _FLS_CALLBACK_INFO* FlsCallback;                                 //0x320
	struct _LIST_ENTRY FlsListHead;                                         //0x328
	VOID* FlsBitmap;                                                        //0x338
	ULONG FlsBitmapBits[4];                                                 //0x340
	ULONG FlsHighIndex;                                                     //0x350
	VOID* WerRegistrationData;                                              //0x358
	VOID* WerShipAssertPtr;                                                 //0x360
	VOID* pContextData;                                                     //0x368
	VOID* pImageHeaderHash;                                                 //0x370
	union
	{
		ULONG TracingFlags;                                                 //0x378
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x378
			ULONG CritSecTracingEnabled : 1;                                  //0x378
			ULONG SpareTracingBits : 30;                                      //0x378
		};
	};
}_MPEB, * PMPEB;


struct _GDI_TEB_BATCH
{
	ULONG Offset;                                                           //0x0
	ULONGLONG HDC;                                                          //0x8
	ULONG Buffer[310];                                                      //0x10
};

typedef struct _TEB
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
	VOID* SystemReserved1[54];                                              //0x110
	LONG ExceptionCode;                                                     //0x2c0
	struct _ACTIVATION_CONTEXT_STACK* ActivationContextStackPointer;        //0x2c8
	UCHAR SpareBytes[24];                                                   //0x2d0
	ULONG TxFsContext;                                                      //0x2e8
	struct _GDI_TEB_BATCH GdiTebBatch;                                      //0x2f0
	struct _CLIENT_ID RealClientId;                                         //0x7d8
	VOID* GdiCachedProcessHandle;                                           //0x7e8
	ULONG GdiClientPID;                                                     //0x7f0
	ULONG GdiClientTID;                                                     //0x7f4
	VOID* GdiThreadLocalInfo;                                               //0x7f8
	ULONGLONG Win32ClientInfo[62];                                          //0x800
	VOID* glDispatchTable[233];                                             //0x9f0
	ULONGLONG glReserved1[29];                                              //0x1138
	VOID* glReserved2;                                                      //0x1220
	VOID* glSectionInfo;                                                    //0x1228
	VOID* glSection;                                                        //0x1230
	VOID* glTable;                                                          //0x1238
	VOID* glCurrentRC;                                                      //0x1240
	VOID* glContext;                                                        //0x1248
	ULONG LastStatusValue;                                                  //0x1250
	struct _UNICODE_STRING StaticUnicodeString;                             //0x1258
	WCHAR StaticUnicodeBuffer[261];                                         //0x1268
	VOID* DeallocationStack;                                                //0x1478
	VOID* TlsSlots[64];                                                     //0x1480
	struct _LIST_ENTRY TlsLinks;                                            //0x1680
	VOID* Vdm;                                                              //0x1690
	VOID* ReservedForNtRpc;                                                 //0x1698
	VOID* DbgSsReserved[2];                                                 //0x16a0
	ULONG HardErrorMode;                                                    //0x16b0
	VOID* Instrumentation[11];                                              //0x16b8
	struct _GUID ActivityId;                                                //0x1710
	VOID* SubProcessTag;                                                    //0x1720
	VOID* EtwLocalData;                                                     //0x1728
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
	VOID* ReservedForPerf;                                                  //0x1750
	VOID* ReservedForOle;                                                   //0x1758
	ULONG WaitingOnLoaderLock;                                              //0x1760
	VOID* SavedPriorityState;                                               //0x1768
	ULONGLONG SoftPatchPtr1;                                                //0x1770
	VOID* ThreadPoolData;                                                   //0x1778
	VOID** TlsExpansionSlots;                                               //0x1780
	VOID* DeallocationBStore;                                               //0x1788
	VOID* BStoreLimit;                                                      //0x1790
	ULONG MuiGeneration;                                                    //0x1798
	ULONG IsImpersonating;                                                  //0x179c
	VOID* NlsCache;                                                         //0x17a0
	VOID* pShimData;                                                        //0x17a8
	ULONG HeapVirtualAffinity;                                              //0x17b0
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
			USHORT SpareSameTebBits : 5;                                      //0x17ee
		};
	};
	VOID* TxnScopeEnterCallback;                                            //0x17f0
	VOID* TxnScopeExitCallback;                                             //0x17f8
	VOID* TxnScopeContext;                                                  //0x1800
	ULONG LockCount;                                                        //0x1808
	ULONG SpareUlong0;                                                      //0x180c
	VOID* ResourceRetValue;                                                 //0x1810

	// For Win10
	VOID* ReservedForWdf;                                                   //0x1818
	ULONGLONG ReservedForCrt;                                               //0x1820
	struct _GUID EffectiveContainerId;                                      //0x1828
}TEB, * PTEB;

EXTERN_C PPEB PsGetProcessPeb(__in PEPROCESS Process);

EXTERN_C PPEB32 PsGetProcessWow64Process(PEPROCESS eprocess);