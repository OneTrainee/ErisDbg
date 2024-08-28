#pragma once

#include <ntifs.h>

struct _KAFFINITY_EX
{
	USHORT Count;                                                           //0x0
	USHORT Size;                                                            //0x2
	ULONG Reserved;                                                         //0x4
	ULONGLONG Bitmap[4];                                                    //0x8
};

union _KEXECUTE_OPTIONS
{
	UCHAR ExecuteDisable : 1;                                                 //0x0
	UCHAR ExecuteEnable : 1;                                                  //0x0
	UCHAR DisableThunkEmulation : 1;                                          //0x0
	UCHAR Permanent : 1;                                                      //0x0
	UCHAR ExecuteDispatchEnable : 1;                                          //0x0
	UCHAR ImageDispatchEnable : 1;                                            //0x0
	UCHAR DisableExceptionChainValidation : 1;                                //0x0
	UCHAR Spare : 1;                                                          //0x0
	volatile UCHAR ExecuteOptions;                                          //0x0
};



typedef struct _MKGDTENTRY64
{
	USHORT LimitLow;
	USHORT BaseLow;
	ULONG Bits;
	ULONG MustBeZero;
	ULONG xxxx;
}MKGDTENTRY64, * PMKGDTENTRY64;

union _KSTACK_COUNT
{
	volatile LONG Value;                                                    //0x0
	volatile ULONG State : 3;                                                 //0x0
	ULONG StackCount : 29;                                                    //0x0
};

struct _KGUARDED_MUTEX
{
	volatile LONG Count;                                                    //0x0
	struct _KTHREAD* Owner;                                                 //0x8
	ULONG Contention;                                                       //0x10
	struct _KGATE Gate;                                                     //0x18
	union
	{
		struct
		{
			SHORT KernelApcDisable;                                         //0x30
			SHORT SpecialApcDisable;                                        //0x32
		};
		ULONG CombinedApcDisable;                                           //0x30
	};
};

struct _MEX_PUSH_LOCK
{
	union
	{
		struct
		{
			ULONGLONG Locked : 1;                                             //0x0
			ULONGLONG Waiting : 1;                                            //0x0
			ULONGLONG Waking : 1;                                             //0x0
			ULONGLONG MultipleShared : 1;                                     //0x0
			ULONGLONG Shared : 60;                                            //0x0
		};
		ULONGLONG Value;                                                    //0x0
		VOID* Ptr;                                                          //0x0
	};
};


typedef struct _KPROCESSWIN7
{
	DISPATCHER_HEADER Header;                                       //0x0
	LIST_ENTRY ProfileListHead;                                     //0x18
	ULONGLONG DirectoryTableBase;                                           //0x28
	LIST_ENTRY ThreadListHead;                                      //0x30
	ULONGLONG ProcessLock;                                                  //0x40
	struct _KAFFINITY_EX Affinity;                                          //0x48
	LIST_ENTRY ReadyListHead;                                       //0x70
	SINGLE_LIST_ENTRY SwapListEntry;                                //0x80
	volatile struct _KAFFINITY_EX ActiveProcessors;                         //0x88
	union
	{
		struct
		{
			volatile LONG AutoAlignment : 1;                                  //0xb0
			volatile LONG DisableBoost : 1;                                   //0xb0
			volatile LONG DisableQuantum : 1;                                 //0xb0
			volatile ULONG ActiveGroupsMask : 4;                              //0xb0
			volatile LONG ReservedFlags : 25;                                 //0xb0
		};
		volatile LONG ProcessFlags;                                         //0xb0
	};
	CHAR BasePriority;                                                      //0xb4
	CHAR QuantumReset;                                                      //0xb5
	UCHAR Visited;                                                          //0xb6
	UCHAR Unused3;                                                          //0xb7
	ULONG ThreadSeed[4];                                                    //0xb8
	USHORT IdealNode[4];                                                    //0xc8
	USHORT IdealGlobalNode;                                                 //0xd0
	union _KEXECUTE_OPTIONS Flags;                                          //0xd2
	UCHAR Unused1;                                                          //0xd3
	ULONG Unused2;                                                          //0xd4
	ULONG Unused4;                                                          //0xd8
	union _KSTACK_COUNT StackCount;                                         //0xdc
	struct _LIST_ENTRY ProcessListEntry;                                    //0xe0
	volatile ULONGLONG CycleTime;                                           //0xf0
	ULONG KernelTime;                                                       //0xf8
	ULONG UserTime;                                                         //0xfc
	VOID* InstrumentationCallback;                                          //0x100
	MKGDTENTRY64 LdtSystemDescriptor;                                 //0x108
	VOID* LdtBaseAddress;                                                   //0x118
	struct _KGUARDED_MUTEX LdtProcessLock;                                  //0x120
	USHORT LdtFreeSelectorHint;                                             //0x158
	USHORT LdtTableLength;                                                  //0x15a
}KPROCESSWIN7, * PKPROCESSWIN7;


typedef struct _EX_FAST_REF
{
	union
	{
		VOID* Object;                                                       //0x0
		ULONGLONG RefCnt : 4;                                                 //0x0
		ULONGLONG Value;                                                    //0x0
	};
}EX_FAST_REF, * PEX_FAST_REF;

struct _HARDWARE_PTE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Write : 1;                                                      //0x0
	ULONGLONG Owner : 1;                                                      //0x0
	ULONGLONG WriteThrough : 1;                                               //0x0
	ULONGLONG CacheDisable : 1;                                               //0x0
	ULONGLONG Accessed : 1;                                                   //0x0
	ULONGLONG Dirty : 1;                                                      //0x0
	ULONGLONG LargePage : 1;                                                  //0x0
	ULONGLONG Global : 1;                                                     //0x0
	ULONGLONG CopyOnWrite : 1;                                                //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG reserved0 : 1;                                                  //0x0
	ULONGLONG PageFrameNumber : 36;                                           //0x0
	ULONGLONG reserved1 : 4;                                                  //0x0
	ULONGLONG SoftwareWsIndex : 11;                                           //0x0
	ULONGLONG NoExecute : 1;                                                  //0x0
};

struct _SE_AUDIT_PROCESS_CREATION_INFO
{
	struct _OBJECT_NAME_INFORMATION* ImageFileName;                         //0x0
};

struct _MMSUPPORT_FLAGS
{
	UCHAR WorkingSetType : 3;                                                 //0x0
	UCHAR ModwriterAttached : 1;                                              //0x0
	UCHAR TrimHard : 1;                                                       //0x0
	UCHAR MaximumWorkingSetHard : 1;                                          //0x0
	UCHAR ForceTrim : 1;                                                      //0x0
	UCHAR MinimumWorkingSetHard : 1;                                          //0x0
	UCHAR SessionMaster : 1;                                                  //0x1
	UCHAR TrimmerState : 2;                                                   //0x1
	UCHAR Reserved : 1;                                                       //0x1
	UCHAR PageStealers : 4;                                                   //0x1
	UCHAR MemoryPriority : 8;                                                 //0x2
	UCHAR WsleDeleted : 1;                                                    //0x3
	UCHAR VmExiting : 1;                                                      //0x3
	UCHAR ExpansionFailed : 1;                                                //0x3
	UCHAR Available : 5;                                                      //0x3
};

struct _MMSUPPORT
{
	struct _MEX_PUSH_LOCK WorkingSetMutex;                                   //0x0
	struct _KGATE* ExitGate;                                                //0x8
	VOID* AccessLog;                                                        //0x10
	struct _LIST_ENTRY WorkingSetExpansionLinks;                            //0x18
	ULONG AgeDistribution[7];                                               //0x28
	ULONG MinimumWorkingSetSize;                                            //0x44
	ULONG WorkingSetSize;                                                   //0x48
	ULONG WorkingSetPrivateSize;                                            //0x4c
	ULONG MaximumWorkingSetSize;                                            //0x50
	ULONG ChargedWslePages;                                                 //0x54
	ULONG ActualWslePages;                                                  //0x58
	ULONG WorkingSetSizeOverhead;                                           //0x5c
	ULONG PeakWorkingSetSize;                                               //0x60
	ULONG HardFaultCount;                                                   //0x64
	struct _MMWSL* VmWorkingSetList;                                        //0x68
	USHORT NextPageColor;                                                   //0x70
	USHORT LastTrimStamp;                                                   //0x72
	ULONG PageFaultCount;                                                   //0x74
	ULONG RepurposeCount;                                                   //0x78
	ULONG Spare[2];                                                         //0x7c
	struct _MMSUPPORT_FLAGS Flags;                                          //0x84
};

struct _ALPC_PROCESS_CONTEXT
{
	struct _MEX_PUSH_LOCK Lock;                                              //0x0
	struct _LIST_ENTRY ViewListHead;                                        //0x8
	volatile ULONGLONG PagedPoolQuotaCache;                                 //0x18
};

typedef struct _MMADDRESS_NODE
{
	union
	{
		LONGLONG Balance : 2;                                                 //0x0
		struct _MMADDRESS_NODE* Parent;                                     //0x0
	} u1;                                                                   //0x0
	struct _MMADDRESS_NODE* LeftChild;                                      //0x8
	struct _MMADDRESS_NODE* RightChild;                                     //0x10
	ULONGLONG StartingVpn;                                                  //0x18
	ULONGLONG EndingVpn;                                                    //0x20
}MMADDRESS_NODE, * PMMADDRESS_NODE;

struct _SEGMENT_FLAGS
{
	ULONG TotalNumberOfPtes4132 : 10;                                         //0x0
	ULONG ExtraSharedWowSubsections : 1;                                      //0x0
	ULONG LargePages : 1;                                                     //0x0
	ULONG WatchProto : 1;                                                     //0x0
	ULONG DebugSymbolsLoaded : 1;                                             //0x0
	ULONG WriteCombined : 1;                                                  //0x0
	ULONG NoCache : 1;                                                        //0x0
	ULONG FloppyMedia : 1;                                                    //0x0
	ULONG DefaultProtectionMask : 5;                                          //0x0
	ULONG Binary32 : 1;                                                       //0x0
	ULONG ContainsDebug : 1;                                                  //0x0
	ULONG Spare : 8;                                                          //0x0
};

struct _MMPTE_HARDWARE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Dirty1 : 1;                                                     //0x0
	ULONGLONG Owner : 1;                                                      //0x0
	ULONGLONG WriteThrough : 1;                                               //0x0
	ULONGLONG CacheDisable : 1;                                               //0x0
	ULONGLONG Accessed : 1;                                                   //0x0
	ULONGLONG Dirty : 1;                                                      //0x0
	ULONGLONG LargePage : 1;                                                  //0x0
	ULONGLONG Global : 1;                                                     //0x0
	ULONGLONG CopyOnWrite : 1;                                                //0x0
	ULONGLONG Unused : 1;                                                     //0x0
	ULONGLONG Write : 1;                                                      //0x0
	ULONGLONG PageFrameNumber : 36;                                           //0x0
	ULONGLONG reserved1 : 4;                                                  //0x0
	ULONGLONG SoftwareWsIndex : 11;                                           //0x0
	ULONGLONG NoExecute : 1;                                                  //0x0
};

struct _MMPTE_PROTOTYPE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Unused0 : 7;                                                    //0x0
	ULONGLONG ReadOnly : 1;                                                   //0x0
	ULONGLONG Unused1 : 1;                                                    //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	LONGLONG ProtoAddress : 48;                                               //0x0
};

struct _MMPTE_SOFTWARE
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG PageFileLow : 4;                                                //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG UsedPageTableEntries : 10;                                      //0x0
	ULONGLONG InStore : 1;                                                    //0x0
	ULONGLONG Reserved : 9;                                                   //0x0
	ULONGLONG PageFileHigh : 32;                                              //0x0
};

struct _MMPTE_LIST
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG OneEntry : 1;                                                   //0x0
	ULONGLONG filler0 : 3;                                                    //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG filler1 : 20;                                                   //0x0
	ULONGLONG NextEntry : 32;                                                 //0x0
};

struct _MMPTE_SUBSECTION
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Unused0 : 4;                                                    //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Unused1 : 5;                                                    //0x0
	LONGLONG SubsectionAddress : 48;                                          //0x0
};

struct _MMPTE_TRANSITION
{
	ULONGLONG Valid : 1;                                                      //0x0
	ULONGLONG Write : 1;                                                      //0x0
	ULONGLONG Owner : 1;                                                      //0x0
	ULONGLONG WriteThrough : 1;                                               //0x0
	ULONGLONG CacheDisable : 1;                                               //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG PageFrameNumber : 36;                                           //0x0
	ULONGLONG Unused : 16;                                                    //0x0
};

struct _MMPTE_TIMESTAMP
{
	ULONGLONG MustBeZero : 1;                                                 //0x0
	ULONGLONG PageFileLow : 4;                                                //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Prototype : 1;                                                  //0x0
	ULONGLONG Transition : 1;                                                 //0x0
	ULONGLONG Reserved : 20;                                                  //0x0
	ULONGLONG GlobalTimeStamp : 32;                                           //0x0
};

struct _MMPTE
{
	union
	{
		ULONGLONG Long;                                                     //0x0
		volatile ULONGLONG VolatileLong;                                    //0x0
		struct _MMPTE_HARDWARE Hard;                                        //0x0
		struct _HARDWARE_PTE Flush;                                         //0x0
		struct _MMPTE_PROTOTYPE Proto;                                      //0x0
		struct _MMPTE_SOFTWARE Soft;                                        //0x0
		struct _MMPTE_TIMESTAMP TimeStamp;                                  //0x0
		struct _MMPTE_TRANSITION Trans;                                     //0x0
		struct _MMPTE_SUBSECTION Subsect;                                   //0x0
		struct _MMPTE_LIST List;                                            //0x0
	} u;                                                                    //0x0
};

typedef struct _MMSECTION_FLAGS
{
	ULONG BeingDeleted : 1;                                                   //0x0
	ULONG BeingCreated : 1;                                                   //0x0
	ULONG BeingPurged : 1;                                                    //0x0
	ULONG NoModifiedWriting : 1;                                              //0x0
	ULONG FailAllIo : 1;                                                      //0x0
	ULONG Image : 1;                                                          //0x0
	ULONG Based : 1;                                                          //0x0
	ULONG File : 1;                                                           //0x0
	ULONG Networked : 1;                                                      //0x0
	ULONG Rom : 1;                                                            //0x0
	ULONG PhysicalMemory : 1;                                                 //0x0
	ULONG CopyOnWrite : 1;                                                    //0x0
	ULONG Reserve : 1;                                                        //0x0
	ULONG Commit : 1;                                                         //0x0
	ULONG Accessed : 1;                                                       //0x0
	ULONG WasPurged : 1;                                                      //0x0
	ULONG UserReference : 1;                                                  //0x0
	ULONG GlobalMemory : 1;                                                   //0x0
	ULONG DeleteOnClose : 1;                                                  //0x0
	ULONG FilePointerNull : 1;                                                //0x0
	ULONG GlobalOnlyPerSession : 1;                                           //0x0
	ULONG SetMappedFileIoComplete : 1;                                        //0x0
	ULONG CollidedFlush : 1;                                                  //0x0
	ULONG NoChange : 1;                                                       //0x0
	ULONG Spare : 1;                                                          //0x0
	ULONG UserWritable : 1;                                                   //0x0
	ULONG PreferredNode : 6;                                                  //0x0
}MMSECTION_FLAGS;

typedef struct _CONTROL_AREA
{
	struct _SEGMENT* Segment;                                               //0x0
	struct _LIST_ENTRY DereferenceList;                                     //0x8
	ULONGLONG NumberOfSectionReferences;                                    //0x18
	ULONGLONG NumberOfPfnReferences;                                        //0x20
	ULONGLONG NumberOfMappedViews;                                          //0x28
	ULONGLONG NumberOfUserReferences;                                       //0x30
	union
	{
		ULONG LongFlags;                                                    //0x38
		struct _MMSECTION_FLAGS Flags;                                      //0x38
	} u;                                                                    //0x38
	ULONG FlushInProgressCount;                                             //0x3c
	struct _EX_FAST_REF FilePointer;                                        //0x40
	volatile LONG ControlAreaLock;                                          //0x48
	union
	{
		ULONG ModifiedWriteCount;                                           //0x4c
		ULONG StartingFrame;                                                //0x4c
	};
	struct _MI_SECTION_CREATION_GATE* WaitingForDeletion;                   //0x50
	union
	{
		struct
		{
			union
			{
				ULONG NumberOfSystemCacheViews;                             //0x58
				ULONG ImageRelocationStartBit;                              //0x58
			};
			union
			{
				volatile LONG WritableUserReferences;                       //0x5c
				struct
				{
					ULONG ImageRelocationSizeIn64k : 16;                      //0x5c
					ULONG Unused : 14;                                        //0x5c
					ULONG BitMap64 : 1;                                       //0x5c
					ULONG ImageActive : 1;                                    //0x5c
				};
			};
			union
			{
				struct _MM_SUBSECTION_AVL_TABLE* SubsectionRoot;            //0x60
				struct _MI_IMAGE_SECURITY_REFERENCE* SeImageStub;           //0x60
			};
		} e2;                                                               //0x58
	} u2;                                                                   //0x58
	volatile LONGLONG LockedPages;                                          //0x68
	struct _LIST_ENTRY ViewList;                                            //0x70
}CONTROL_AREA, * PCONTROL_AREA;

typedef struct _SEGMENT
{
	struct _CONTROL_AREA* ControlArea;                                      //0x0
	ULONG TotalNumberOfPtes;                                                //0x8
	struct _SEGMENT_FLAGS SegmentFlags;                                     //0xc
	ULONGLONG NumberOfCommittedPages;                                       //0x10
	ULONGLONG SizeOfSegment;                                                //0x18
	union
	{
		struct _MMEXTEND_INFO* ExtendInfo;                                  //0x20
		VOID* BasedAddress;                                                 //0x20
	};
	struct _MEX_PUSH_LOCK SegmentLock;                                       //0x28
	union
	{
		ULONGLONG ImageCommitment;                                          //0x30
		struct _EPROCESS* CreatingProcess;                                  //0x30
	} u1;                                                                   //0x30
	union
	{
		struct _MI_SECTION_IMAGE_INFORMATION* ImageInformation;             //0x38
		VOID* FirstMappedVa;                                                //0x38
	} u2;                                                                   //0x38
	struct _MMPTE* PrototypePte;                                            //0x40
	struct _MMPTE ThePtes[1];                                               //0x48
}SEGMENT, * PSEGMENT;

struct _MM_AVL_TABLE
{
	struct _MMADDRESS_NODE BalancedRoot;                                    //0x0
	ULONGLONG DepthOfTree : 5;                                                //0x28
	ULONGLONG Unused : 3;                                                     //0x28
	ULONGLONG NumberGenericTableElements : 56;                                //0x28
	VOID* NodeHint;                                                         //0x30
	VOID* NodeFreeHint;                                                     //0x38
};

typedef struct _EPROCESSWIN7
{
	KPROCESSWIN7 Pcb;                                                   //0x0
	struct _MEX_PUSH_LOCK ProcessLock;                                       //0x160
	LARGE_INTEGER CreateTime;                                        //0x168
	LARGE_INTEGER ExitTime;                                          //0x170
	EX_RUNDOWN_REF RundownProtect;                                  //0x178
	VOID* UniqueProcessId;                                                  //0x180
	struct _LIST_ENTRY ActiveProcessLinks;                                  //0x188
	ULONGLONG ProcessQuotaUsage[2];                                         //0x198
	ULONGLONG ProcessQuotaPeak[2];                                          //0x1a8
	volatile ULONGLONG CommitCharge;                                        //0x1b8
	struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                               //0x1c0
	struct _PS_CPU_QUOTA_BLOCK* CpuQuotaBlock;                              //0x1c8
	ULONGLONG PeakVirtualSize;                                              //0x1d0
	ULONGLONG VirtualSize;                                                  //0x1d8
	struct _LIST_ENTRY SessionProcessLinks;                                 //0x1e0
	VOID* DebugPort;                                                        //0x1f0
	union
	{
		VOID* ExceptionPortData;                                            //0x1f8
		ULONGLONG ExceptionPortValue;                                       //0x1f8
		ULONGLONG ExceptionPortState : 3;                                     //0x1f8
	};
	struct _HANDLE_TABLE* ObjectTable;                                      //0x200
	struct _EX_FAST_REF Token;                                              //0x208
	ULONGLONG WorkingSetPage;                                               //0x210
	struct _MEX_PUSH_LOCK AddressCreationLock;                               //0x218
	struct _ETHREAD* RotateInProgress;                                      //0x220
	struct _ETHREAD* ForkInProgress;                                        //0x228
	ULONGLONG HardwareTrigger;                                              //0x230
	struct _MM_AVL_TABLE* PhysicalVadRoot;                                  //0x238
	VOID* CloneRoot;                                                        //0x240
	volatile ULONGLONG NumberOfPrivatePages;                                //0x248
	volatile ULONGLONG NumberOfLockedPages;                                 //0x250
	VOID* Win32Process;                                                     //0x258
	struct _EJOB* volatile Job;                                             //0x260
	VOID* SectionObject;                                                    //0x268
	VOID* SectionBaseAddress;                                               //0x270
	ULONG Cookie;                                                           //0x278
	ULONG UmsScheduledThreads;                                              //0x27c
	struct _PAGEFAULT_HISTORY* WorkingSetWatch;                             //0x280
	VOID* Win32WindowStation;                                               //0x288
	VOID* InheritedFromUniqueProcessId;                                     //0x290
	VOID* LdtInformation;                                                   //0x298
	VOID* Spare;                                                            //0x2a0
	ULONGLONG ConsoleHostProcess;                                           //0x2a8
	VOID* DeviceMap;                                                        //0x2b0
	VOID* EtwDataSource;                                                    //0x2b8
	VOID* FreeTebHint;                                                      //0x2c0
	VOID* FreeUmsTebHint;                                                   //0x2c8
	union
	{
		struct _HARDWARE_PTE PageDirectoryPte;                              //0x2d0
		ULONGLONG Filler;                                                   //0x2d0
	};
	VOID* Session;                                                          //0x2d8
	UCHAR ImageFileName[15];                                                //0x2e0
	UCHAR PriorityClass;                                                    //0x2ef
	struct _LIST_ENTRY JobLinks;                                            //0x2f0
	VOID* LockedPagesList;                                                  //0x300
	struct _LIST_ENTRY ThreadListHead;                                      //0x308
	VOID* SecurityPort;                                                     //0x318
	VOID* Wow64Process;                                                     //0x320
	volatile ULONG ActiveThreads;                                           //0x328
	ULONG ImagePathHash;                                                    //0x32c
	ULONG DefaultHardErrorProcessing;                                       //0x330
	LONG LastThreadExitStatus;                                              //0x334
	struct _PEB* Peb;                                                       //0x338
	struct _EX_FAST_REF PrefetchTrace;                                      //0x340
	union _LARGE_INTEGER ReadOperationCount;                                //0x348
	union _LARGE_INTEGER WriteOperationCount;                               //0x350
	union _LARGE_INTEGER OtherOperationCount;                               //0x358
	union _LARGE_INTEGER ReadTransferCount;                                 //0x360
	union _LARGE_INTEGER WriteTransferCount;                                //0x368
	union _LARGE_INTEGER OtherTransferCount;                                //0x370
	ULONGLONG CommitChargeLimit;                                            //0x378
	volatile ULONGLONG CommitChargePeak;                                    //0x380
	VOID* AweInfo;                                                          //0x388
	struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;      //0x390
	struct _MMSUPPORT Vm;                                                   //0x398
	struct _LIST_ENTRY MmProcessLinks;                                      //0x420
	VOID* HighestUserAddress;                                               //0x430
	ULONG ModifiedPageCount;                                                //0x438
	union
	{
		ULONG Flags2;                                                       //0x43c
		struct
		{
			ULONG JobNotReallyActive : 1;                                     //0x43c
			ULONG AccountingFolded : 1;                                       //0x43c
			ULONG NewProcessReported : 1;                                     //0x43c
			ULONG ExitProcessReported : 1;                                    //0x43c
			ULONG ReportCommitChanges : 1;                                    //0x43c
			ULONG LastReportMemory : 1;                                       //0x43c
			ULONG ReportPhysicalPageChanges : 1;                              //0x43c
			ULONG HandleTableRundown : 1;                                     //0x43c
			ULONG NeedsHandleRundown : 1;                                     //0x43c
			ULONG RefTraceEnabled : 1;                                        //0x43c
			ULONG NumaAware : 1;                                              //0x43c
			ULONG ProtectedProcess : 1;                                       //0x43c
			ULONG DefaultPagePriority : 3;                                    //0x43c
			ULONG PrimaryTokenFrozen : 1;                                     //0x43c
			ULONG ProcessVerifierTarget : 1;                                  //0x43c
			ULONG StackRandomizationDisabled : 1;                             //0x43c
			ULONG AffinityPermanent : 1;                                      //0x43c
			ULONG AffinityUpdateEnable : 1;                                   //0x43c
			ULONG PropagateNode : 1;                                          //0x43c
			ULONG ExplicitAffinity : 1;                                       //0x43c
		};
	};
	union
	{
		ULONG Flags;                                                        //0x440
		struct
		{
			ULONG CreateReported : 1;                                         //0x440
			ULONG NoDebugInherit : 1;                                         //0x440
			ULONG ProcessExiting : 1;                                         //0x440
			ULONG ProcessDelete : 1;                                          //0x440
			ULONG Wow64SplitPages : 1;                                        //0x440
			ULONG VmDeleted : 1;                                              //0x440
			ULONG OutswapEnabled : 1;                                         //0x440
			ULONG Outswapped : 1;                                             //0x440
			ULONG ForkFailed : 1;                                             //0x440
			ULONG Wow64VaSpace4Gb : 1;                                        //0x440
			ULONG AddressSpaceInitialized : 2;                                //0x440
			ULONG SetTimerResolution : 1;                                     //0x440
			ULONG BreakOnTermination : 1;                                     //0x440
			ULONG DeprioritizeViews : 1;                                      //0x440
			ULONG WriteWatch : 1;                                             //0x440
			ULONG ProcessInSession : 1;                                       //0x440
			ULONG OverrideAddressSpace : 1;                                   //0x440
			ULONG HasAddressSpace : 1;                                        //0x440
			ULONG LaunchPrefetched : 1;                                       //0x440
			ULONG InjectInpageErrors : 1;                                     //0x440
			ULONG VmTopDown : 1;                                              //0x440
			ULONG ImageNotifyDone : 1;                                        //0x440
			ULONG PdeUpdateNeeded : 1;                                        //0x440
			ULONG VdmAllowed : 1;                                             //0x440
			ULONG CrossSessionCreate : 1;                                     //0x440
			ULONG ProcessInserted : 1;                                        //0x440
			ULONG DefaultIoPriority : 3;                                      //0x440
			ULONG ProcessSelfDelete : 1;                                      //0x440
			ULONG SetTimerResolutionLink : 1;                                 //0x440
		};
	};
	LONG ExitStatus;                                                        //0x444
	struct _MM_AVL_TABLE VadRoot;                                           //0x448
	struct _ALPC_PROCESS_CONTEXT AlpcContext;                               //0x488
	struct _LIST_ENTRY TimerResolutionLink;                                 //0x4a8
	ULONG RequestedTimerResolution;                                         //0x4b8
	ULONG ActiveThreadsHighWatermark;                                       //0x4bc
	ULONG SmallestTimerResolution;                                          //0x4c0
	struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x4c8
}EPROCESSWIN7, * PEPROCESSWIN7;


union _PS_CLIENT_SECURITY_CONTEXT
{
	ULONGLONG ImpersonationData;                                            //0x0
	VOID* ImpersonationToken;                                               //0x0
	ULONGLONG ImpersonationLevel : 2;                                         //0x0
	ULONGLONG EffectiveOnly : 1;                                              //0x0
};

union _KWAIT_STATUS_REGISTER
{
	UCHAR Flags;                                                            //0x0
	UCHAR State : 2;                                                          //0x0
	UCHAR Affinity : 1;                                                       //0x0
	UCHAR Priority : 1;                                                       //0x0
	UCHAR Apc : 1;                                                            //0x0
	UCHAR UserApc : 1;                                                        //0x0
	UCHAR Alert : 1;                                                          //0x0
	UCHAR Unused : 1;                                                         //0x0
};

typedef struct _KTHREADWIN7
{
	struct _DISPATCHER_HEADER Header;                                       //0x0
	volatile ULONGLONG CycleTime;                                           //0x18
	ULONGLONG QuantumTarget;                                                //0x20
	VOID* InitialStack;                                                     //0x28
	VOID* volatile StackLimit;                                              //0x30
	VOID* KernelStack;                                                      //0x38
	ULONGLONG ThreadLock;                                                   //0x40
	union _KWAIT_STATUS_REGISTER WaitRegister;                              //0x48
	volatile UCHAR Running;                                                 //0x49
	UCHAR Alerted[2];                                                       //0x4a
	union
	{
		struct
		{
			ULONG KernelStackResident : 1;                                    //0x4c
			ULONG ReadyTransition : 1;                                        //0x4c
			ULONG ProcessReadyQueue : 1;                                      //0x4c
			ULONG WaitNext : 1;                                               //0x4c
			ULONG SystemAffinityActive : 1;                                   //0x4c
			ULONG Alertable : 1;                                              //0x4c
			ULONG GdiFlushActive : 1;                                         //0x4c
			ULONG UserStackWalkActive : 1;                                    //0x4c
			ULONG ApcInterruptRequest : 1;                                    //0x4c
			ULONG ForceDeferSchedule : 1;                                     //0x4c
			ULONG QuantumEndMigrate : 1;                                      //0x4c
			ULONG UmsDirectedSwitchEnable : 1;                                //0x4c
			ULONG TimerActive : 1;                                            //0x4c
			ULONG SystemThread : 1;                                           //0x4c
			ULONG Reserved : 18;                                              //0x4c
		};
		LONG MiscFlags;                                                     //0x4c
	};
	union
	{
		struct _KAPC_STATE ApcState;                                        //0x50
		struct
		{
			UCHAR ApcStateFill[43];                                         //0x50
			CHAR Priority;                                                  //0x7b
			volatile ULONG NextProcessor;                                   //0x7c
		};
	};
	volatile ULONG DeferredProcessor;                                       //0x80
	ULONGLONG ApcQueueLock;                                                 //0x88
	volatile LONGLONG WaitStatus;                                           //0x90
	struct _KWAIT_BLOCK* WaitBlockList;                                     //0x98
	union
	{
		struct _LIST_ENTRY WaitListEntry;                                   //0xa0
		struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0xa0
	};
	struct _KQUEUE* volatile Queue;                                         //0xb0
	VOID* Teb;                                                              //0xb8
	struct _KTIMER Timer;                                                   //0xc0
	union
	{
		struct
		{
			volatile ULONG AutoAlignment : 1;                                 //0x100
			volatile ULONG DisableBoost : 1;                                  //0x100
			volatile ULONG EtwStackTraceApc1Inserted : 1;                     //0x100
			volatile ULONG EtwStackTraceApc2Inserted : 1;                     //0x100
			volatile ULONG CalloutActive : 1;                                 //0x100
			volatile ULONG ApcQueueable : 1;                                  //0x100
			volatile ULONG EnableStackSwap : 1;                               //0x100
			volatile ULONG GuiThread : 1;                                     //0x100
			volatile ULONG UmsPerformingSyscall : 1;                          //0x100
			volatile ULONG VdmSafe : 1;                                       //0x100
			volatile ULONG UmsDispatched : 1;                                 //0x100
			volatile ULONG ReservedFlags : 21;                                //0x100
		};
		volatile LONG ThreadFlags;                                          //0x100
	};
	ULONG Spare0;                                                           //0x104
	union
	{
		struct _KWAIT_BLOCK WaitBlock[4];                                   //0x108
		struct
		{
			UCHAR WaitBlockFill4[44];                                       //0x108
			ULONG ContextSwitches;                                          //0x134
		};
		struct
		{
			UCHAR WaitBlockFill5[92];                                       //0x108
			volatile UCHAR State;                                           //0x164
			CHAR NpxState;                                                  //0x165
			UCHAR WaitIrql;                                                 //0x166
			CHAR WaitMode;                                                  //0x167
		};
		struct
		{
			UCHAR WaitBlockFill6[140];                                      //0x108
			ULONG WaitTime;                                                 //0x194
		};
		struct
		{
			UCHAR WaitBlockFill7[168];                                      //0x108
			VOID* TebMappedLowVa;                                           //0x1b0
			struct _UMS_CONTROL_BLOCK* Ucb;                                 //0x1b8
		};
		struct
		{
			UCHAR WaitBlockFill8[188];                                      //0x108
			union
			{
				struct
				{
					SHORT KernelApcDisable;                                 //0x1c4
					SHORT SpecialApcDisable;                                //0x1c6
				};
				ULONG CombinedApcDisable;                                   //0x1c4
			};
		};
	};
	struct _LIST_ENTRY QueueListEntry;                                      //0x1c8
	struct _KTRAP_FRAME* TrapFrame;                                         //0x1d8
	VOID* FirstArgument;                                                    //0x1e0
	union
	{
		VOID* CallbackStack;                                                //0x1e8
		ULONGLONG CallbackDepth;                                            //0x1e8
	};
	UCHAR ApcStateIndex;                                                    //0x1f0
	CHAR BasePriority;                                                      //0x1f1
	union
	{
		CHAR PriorityDecrement;                                             //0x1f2
		struct
		{
			UCHAR ForegroundBoost : 4;                                        //0x1f2
			UCHAR UnusualBoost : 4;                                           //0x1f2
		};
	};
	UCHAR Preempted;                                                        //0x1f3
	UCHAR AdjustReason;                                                     //0x1f4
	CHAR AdjustIncrement;                                                   //0x1f5
	CHAR PreviousMode;                                                      //0x1f6
	CHAR Saturation;                                                        //0x1f7
	ULONG SystemCallNumber;                                                 //0x1f8
	ULONG FreezeCount;                                                      //0x1fc
	volatile struct _GROUP_AFFINITY UserAffinity;                           //0x200
	struct _KPROCESS* Process;                                              //0x210
	volatile struct _GROUP_AFFINITY Affinity;                               //0x218
	ULONG IdealProcessor;                                                   //0x228
	ULONG UserIdealProcessor;                                               //0x22c
	struct _KAPC_STATE* ApcStatePointer[2];                                 //0x230
	union
	{
		struct _KAPC_STATE SavedApcState;                                   //0x240
		struct
		{
			UCHAR SavedApcStateFill[43];                                    //0x240
			UCHAR WaitReason;                                               //0x26b
			CHAR SuspendCount;                                              //0x26c
			CHAR Spare1;                                                    //0x26d
			UCHAR CodePatchInProgress;                                      //0x26e
		};
	};
	VOID* volatile Win32Thread;                                             //0x270
	VOID* StackBase;                                                        //0x278
	union
	{
		struct _KAPC SuspendApc;                                            //0x280
		struct
		{
			UCHAR SuspendApcFill0[1];                                       //0x280
			UCHAR ResourceIndex;                                            //0x281
		};
		struct
		{
			UCHAR SuspendApcFill1[3];                                       //0x280
			UCHAR QuantumReset;                                             //0x283
		};
		struct
		{
			UCHAR SuspendApcFill2[4];                                       //0x280
			ULONG KernelTime;                                               //0x284
		};
		struct
		{
			UCHAR SuspendApcFill3[64];                                      //0x280
			struct _KPRCB* volatile WaitPrcb;                               //0x2c0
		};
		struct
		{
			UCHAR SuspendApcFill4[72];                                      //0x280
			VOID* LegoData;                                                 //0x2c8
		};
		struct
		{
			UCHAR SuspendApcFill5[83];                                      //0x280
			UCHAR LargeStack;                                               //0x2d3
			ULONG UserTime;                                                 //0x2d4
		};
	};
	union
	{
		struct _KSEMAPHORE SuspendSemaphore;                                //0x2d8
		struct
		{
			UCHAR SuspendSemaphorefill[28];                                 //0x2d8
			ULONG SListFaultCount;                                          //0x2f4
		};
	};
	struct _LIST_ENTRY ThreadListEntry;                                     //0x2f8
	struct _LIST_ENTRY MutantListHead;                                      //0x308
	VOID* SListFaultAddress;                                                //0x318
	LONGLONG ReadOperationCount;                                            //0x320
	LONGLONG WriteOperationCount;                                           //0x328
	LONGLONG OtherOperationCount;                                           //0x330
	LONGLONG ReadTransferCount;                                             //0x338
	LONGLONG WriteTransferCount;                                            //0x340
	LONGLONG OtherTransferCount;                                            //0x348
	struct _KTHREAD_COUNTERS* ThreadCounters; //0x350
	XSAVE_FORMAT* StateSaveArea;   //注意有些没有打过系统补丁的 没有结构 请自行注释，不然调试器会出问题
	XSTATE_SAVE* XStateSave;                                        //0x358
}KTHREADWIN7, * PKTHREADWIN7;
//0x498 bytes (sizeof)
typedef struct _ETHREADWIN7
{
	KTHREADWIN7 Tcb;                                                    //0x0
	union _LARGE_INTEGER CreateTime;                                        //0x360
	union
	{
		union _LARGE_INTEGER ExitTime;                                      //0x368
		struct _LIST_ENTRY KeyedWaitChain;                                  //0x368
	};
	LONG ExitStatus;                                                        //0x378
	union
	{
		struct _LIST_ENTRY PostBlockList;                                   //0x380
		struct
		{
			VOID* ForwardLinkShadow;                                        //0x380
			VOID* StartAddress;                                             //0x388
		};
	};
	union
	{
		struct _TERMINATION_PORT* TerminationPort;                          //0x390
		struct _ETHREAD* ReaperLink;                                        //0x390
		VOID* KeyedWaitValue;                                               //0x390
	};
	ULONGLONG ActiveTimerListLock;                                          //0x398
	struct _LIST_ENTRY ActiveTimerListHead;                                 //0x3a0
	struct _CLIENT_ID Cid;                                                  //0x3b0
	union
	{
		struct _KSEMAPHORE KeyedWaitSemaphore;                              //0x3c0
		struct _KSEMAPHORE AlpcWaitSemaphore;                               //0x3c0
	};
	union _PS_CLIENT_SECURITY_CONTEXT ClientSecurity;                       //0x3e0
	struct _LIST_ENTRY IrpList;                                             //0x3e8
	ULONGLONG TopLevelIrp;                                                  //0x3f8
	struct _DEVICE_OBJECT* DeviceToVerify;                                  //0x400
	union _PSP_CPU_QUOTA_APC* CpuQuotaApc;                                  //0x408
	VOID* Win32StartAddress;                                                //0x410
	VOID* LegacyPowerObject;                                                //0x418
	struct _LIST_ENTRY ThreadListEntry;                                     //0x420
	struct _EX_RUNDOWN_REF RundownProtect;                                  //0x430
	struct _MEX_PUSH_LOCK ThreadLock;                                        //0x438
	ULONG ReadClusterSize;                                                  //0x440
	volatile LONG MmLockOrdering;                                           //0x444
	union
	{
		ULONG CrossThreadFlags;                                             //0x448
		struct
		{
			ULONG Terminated : 1;                                             //0x448
			ULONG ThreadInserted : 1;                                         //0x448
			ULONG HideFromDebugger : 1;                                       //0x448
			ULONG ActiveImpersonationInfo : 1;                                //0x448
			ULONG Reserved : 1;                                               //0x448
			ULONG HardErrorsAreDisabled : 1;                                  //0x448
			ULONG BreakOnTermination : 1;                                     //0x448
			ULONG SkipCreationMsg : 1;                                        //0x448
			ULONG SkipTerminationMsg : 1;                                     //0x448
			ULONG CopyTokenOnOpen : 1;                                        //0x448
			ULONG ThreadIoPriority : 3;                                       //0x448
			ULONG ThreadPagePriority : 3;                                     //0x448
			ULONG RundownFail : 1;                                            //0x448
			ULONG NeedsWorkingSetAging : 1;                                   //0x448
		};
	};
	union
	{
		ULONG SameThreadPassiveFlags;                                       //0x44c
		struct
		{
			ULONG ActiveExWorker : 1;                                         //0x44c
			ULONG ExWorkerCanWaitUser : 1;                                    //0x44c
			ULONG MemoryMaker : 1;                                            //0x44c
			ULONG ClonedThread : 1;                                           //0x44c
			ULONG KeyedEventInUse : 1;                                        //0x44c
			ULONG RateApcState : 2;                                           //0x44c
			ULONG SelfTerminate : 1;                                          //0x44c
		};
	};
	union
	{
		ULONG SameThreadApcFlags;                                           //0x450
		struct
		{
			UCHAR Spare : 1;                                                  //0x450
			volatile UCHAR StartAddressInvalid : 1;                           //0x450
			UCHAR EtwPageFaultCalloutActive : 1;                              //0x450
			UCHAR OwnsProcessWorkingSetExclusive : 1;                         //0x450
			UCHAR OwnsProcessWorkingSetShared : 1;                            //0x450
			UCHAR OwnsSystemCacheWorkingSetExclusive : 1;                     //0x450
			UCHAR OwnsSystemCacheWorkingSetShared : 1;                        //0x450
			UCHAR OwnsSessionWorkingSetExclusive : 1;                         //0x450
			UCHAR OwnsSessionWorkingSetShared : 1;                            //0x451
			UCHAR OwnsProcessAddressSpaceExclusive : 1;                       //0x451
			UCHAR OwnsProcessAddressSpaceShared : 1;                          //0x451
			UCHAR SuppressSymbolLoad : 1;                                     //0x451
			UCHAR Prefetching : 1;                                            //0x451
			UCHAR OwnsDynamicMemoryShared : 1;                                //0x451
			UCHAR OwnsChangeControlAreaExclusive : 1;                         //0x451
			UCHAR OwnsChangeControlAreaShared : 1;                            //0x451
			UCHAR OwnsPagedPoolWorkingSetExclusive : 1;                       //0x452
			UCHAR OwnsPagedPoolWorkingSetShared : 1;                          //0x452
			UCHAR OwnsSystemPtesWorkingSetExclusive : 1;                      //0x452
			UCHAR OwnsSystemPtesWorkingSetShared : 1;                         //0x452
			UCHAR TrimTrigger : 2;                                            //0x452
			UCHAR Spare1 : 2;                                                 //0x452
			UCHAR PriorityRegionActive;                                     //0x453
		};
	};
	UCHAR CacheManagerActive;                                               //0x454
	UCHAR DisablePageFaultClustering;                                       //0x455
	UCHAR ActiveFaultCount;                                                 //0x456
	UCHAR LockOrderState;                                                   //0x457
	ULONGLONG AlpcMessageId;                                                //0x458
	union
	{
		VOID* AlpcMessage;                                                  //0x460
		ULONG AlpcReceiveAttributeSet;                                      //0x460
	};
	struct _LIST_ENTRY AlpcWaitListEntry;                                   //0x468
	ULONG CacheManagerCount;                                                //0x478
	ULONG IoBoostCount;                                                     //0x47c
	ULONGLONG IrpListLock;                                                  //0x480
	VOID* ReservedForSynchTracking;                                         //0x488
	struct _SINGLE_LIST_ENTRY CmCallbackListHead;                           //0x490
}ETHREADWIN7, * PETHREADWIN7;

struct _MMVAD_FLAGS
{
	ULONGLONG CommitCharge : 51;                                              //0x0
	ULONGLONG NoChange : 1;                                                   //0x0
	ULONGLONG VadType : 3;                                                    //0x0
	ULONGLONG MemCommit : 1;                                                  //0x0
	ULONGLONG Protection : 5;                                                 //0x0
	ULONGLONG Spare : 2;                                                      //0x0
	ULONGLONG PrivateMemory : 1;                                              //0x0
};

struct _MMVAD_FLAGS3
{
	ULONGLONG PreferredNode : 6;                                              //0x0
	ULONGLONG Teb : 1;                                                        //0x0
	ULONGLONG Spare : 1;                                                      //0x0
	ULONGLONG SequentialAccess : 1;                                           //0x0
	ULONGLONG LastSequentialTrim : 15;                                        //0x0
	ULONGLONG Spare2 : 8;                                                     //0x0
	ULONGLONG LargePageCreating : 1;                                          //0x0
	ULONGLONG Spare3 : 31;                                                    //0x0
};

struct _MMVAD_FLAGS2
{
	ULONG FileOffset : 24;                                                    //0x0
	ULONG SecNoChange : 1;                                                    //0x0
	ULONG OneSecured : 1;                                                     //0x0
	ULONG MultipleSecured : 1;                                                //0x0
	ULONG Spare : 1;                                                          //0x0
	ULONG LongVad : 1;                                                        //0x0
	ULONG ExtendableFile : 1;                                                 //0x0
	ULONG Inherit : 1;                                                        //0x0
	ULONG CopyOnWrite : 1;                                                    //0x0
};

typedef struct _MMVAD
{
	union
	{
		LONGLONG Balance : 2;                                                 //0x0
		struct _MMVAD* Parent;                                              //0x0
	} u1;                                                                   //0x0
	struct _MMVAD* LeftChild;                                               //0x8
	struct _MMVAD* RightChild;                                              //0x10
	ULONGLONG StartingVpn;                                                  //0x18
	ULONGLONG EndingVpn;                                                    //0x20
	union
	{
		ULONGLONG LongFlags;                                                //0x28
		struct _MMVAD_FLAGS VadFlags;                                       //0x28
	} u;                                                                    //0x28
	struct _MEX_PUSH_LOCK PushLock;                                          //0x30
	union
	{
		ULONGLONG LongFlags3;                                               //0x38
		struct _MMVAD_FLAGS3 VadFlags3;                                     //0x38
	} u5;                                                                   //0x38
	union
	{
		ULONG LongFlags2;                                                   //0x40
		struct _MMVAD_FLAGS2 VadFlags2;                                     //0x40
	} u2;                                                                   //0x40
	union
	{
		struct _SUBSECTION* Subsection;                                     //0x48
		struct _MSUBSECTION* MappedSubsection;                              //0x48
	};
	struct _MMPTE* FirstPrototypePte;                                       //0x50
	struct _MMPTE* LastContiguousPte;                                       //0x58
	struct _LIST_ENTRY ViewLinks;                                           //0x60
	struct _EPROCESS* VadsProcess;                                          //0x70
}MMVAD, * PMMVAD;

#define PS_PROCESS_FLAGS_CREATE_REPORTED        0x00000001UL // Create process debug call has occurred
#define PS_PROCESS_FLAGS_NO_DEBUG_INHERIT       0x00000002UL // Don't inherit debug port
#define PS_PROCESS_FLAGS_PROCESS_EXITING        0x00000004UL // PspExitProcess entered
#define PS_PROCESS_FLAGS_PROCESS_DELETE         0x00000008UL // Delete process has been issued
#define PS_PROCESS_FLAGS_WOW64_SPLIT_PAGES      0x00000010UL // Wow64 split pages
#define PS_PROCESS_FLAGS_VM_DELETED             0x00000020UL // VM is deleted
#define PS_PROCESS_FLAGS_OUTSWAP_ENABLED        0x00000040UL // Outswap enabled
#define PS_PROCESS_FLAGS_OUTSWAPPED             0x00000080UL // Outswapped
#define PS_PROCESS_FLAGS_FORK_FAILED            0x00000100UL // Fork status
#define PS_PROCESS_FLAGS_WOW64_4GB_VA_SPACE     0x00000200UL // Wow64 process with 4gb virtual address space
#define PS_PROCESS_FLAGS_ADDRESS_SPACE1         0x00000400UL // Addr space state1
#define PS_PROCESS_FLAGS_ADDRESS_SPACE2         0x00000800UL // Addr space state2
#define PS_PROCESS_FLAGS_SET_TIMER_RESOLUTION   0x00001000UL // SetTimerResolution has been called
#define PS_PROCESS_FLAGS_BREAK_ON_TERMINATION   0x00002000UL // Break on process termination
#define PS_PROCESS_FLAGS_CREATING_SESSION       0x00004000UL // Process is creating a session
#define PS_PROCESS_FLAGS_USING_WRITE_WATCH      0x00008000UL // Process is using the write watch APIs
#define PS_PROCESS_FLAGS_IN_SESSION             0x00010000UL // Process is in a session
#define PS_PROCESS_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00020000UL // Process must use native address space (Win64 only)
#define PS_PROCESS_FLAGS_HAS_ADDRESS_SPACE      0x00040000UL // This process has an address space
#define PS_PROCESS_FLAGS_LAUNCH_PREFETCHED      0x00080000UL // Process launch was prefetched
#define PS_PROCESS_INJECT_INPAGE_ERRORS         0x00100000UL // Process should be given inpage errors - hardcoded in trap.asm too
#define PS_PROCESS_FLAGS_VM_TOP_DOWN            0x00200000UL // Process memory allocations default to top-down
#define PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE      0x00400000UL // We have sent a message for this image
#define PS_PROCESS_FLAGS_PDE_UPDATE_NEEDED      0x00800000UL // The system PDEs need updating for this process (NT32 only)
#define PS_PROCESS_FLAGS_VDM_ALLOWED            0x01000000UL // Process allowed to invoke NTVDM support
#define PS_PROCESS_FLAGS_SMAP_ALLOWED           0x02000000UL // Process allowed to invoke SMAP support
#define PS_PROCESS_FLAGS_CREATE_FAILED          0x04000000UL // Process create failed

#define PS_PROCESS_FLAGS_DEFAULT_IO_PRIORITY    0x38000000UL // The default I/O priority for created threads. (3 bits)

#define PS_PROCESS_FLAGS_PRIORITY_SHIFT         27

#define PS_PROCESS_FLAGS_EXECUTE_SPARE1         0x40000000UL //
#define PS_PROCESS_FLAGS_EXECUTE_SPARE2         0x80000000UL //


#define PS_CROSS_THREAD_FLAGS_TERMINATED           0x00000001UL

//
// Thread create failed
//

#define PS_CROSS_THREAD_FLAGS_DEADTHREAD           0x00000002UL

//
// Debugger isn't shown this thread
//

#define PS_CROSS_THREAD_FLAGS_HIDEFROMDBG          0x00000004UL

//
// Thread is impersonating
//

#define PS_CROSS_THREAD_FLAGS_IMPERSONATING        0x00000008UL

//
// This is a system thread
//

#define PS_CROSS_THREAD_FLAGS_SYSTEM               0x00000010UL

//
// Hard errors are disabled for this thread
//

#define PS_CROSS_THREAD_FLAGS_HARD_ERRORS_DISABLED 0x00000020UL

//
// We should break in when this thread is terminated
//

#define PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION 0x00000040UL

//
// This thread should skip sending its create thread message
//
#define PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG    0x00000080UL

//
// This thread should skip sending its final thread termination message
//
#define PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG 0x00000100UL


#define THREAD_TERMINATE						(0x0001)  
#define THREAD_SUSPEND_RESUME					(0x0002)  
#define THREAD_GET_CONTEXT						(0x0008)  
#define THREAD_SET_CONTEXT						(0x0010)  
#define THREAD_QUERY_INFORMATION				(0x0040)  
#define THREAD_SET_INFORMATION					(0x0020)  
#define THREAD_SET_THREAD_TOKEN					(0x0080)
#define THREAD_IMPERSONATE						(0x0100)
#define THREAD_DIRECT_IMPERSONATION				(0x0200)

#define PROCESS_TERMINATE         (0x0001)  // winnt
#define PROCESS_CREATE_THREAD     (0x0002)  // winnt
#define PROCESS_SET_SESSIONID     (0x0004)  // winnt
#define PROCESS_VM_OPERATION      (0x0008)  // winnt
#define PROCESS_VM_READ           (0x0010)  // winnt
#define PROCESS_VM_WRITE          (0x0020)  // winnt
#define PROCESS_DUP_HANDLE        (0x0040)  // winnt
#define PROCESS_CREATE_PROCESS    (0x0080)  // winnt
#define PROCESS_SET_QUOTA         (0x0100)  // winnt
#define PROCESS_SET_INFORMATION   (0x0200)  // winnt
#define PROCESS_QUERY_INFORMATION (0x0400)  // winnt
#define PROCESS_SET_PORT          (0x0800)
#define PROCESS_SUSPEND_RESUME    (0x0800)  // winnt


EXTERN_C NTSTATUS MmCopyVirtualMemory(
	IN PEPROCESS FromProcess,
	IN CONST VOID* FromAddress,
	IN PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN SIZE_T BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);