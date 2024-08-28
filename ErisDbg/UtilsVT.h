#pragma once
#include<ntifs.h>
#include"ia32_type.h"

ULONG64 UtilReadMsr64(Msr msr);
VOID UtilWriteMsr64(Msr msr, ULONG64 value);
ULONG64 UtilPaFromVa(void* va);

enum class VmxStatus : unsigned __int8 {
	kOk = 0,                  //!< Operation succeeded
	kErrorWithStatus = 1,     //!< Operation failed with extended status available
	kErrorWithoutStatus = 2,  //!< Operation failed without status available
};

VmxStatus UtilVmWrite(VmcsField field, ULONG64 field_value);
ULONG_PTR UtilVmRead(VmcsField field);
VmxStatus UtilInvvpidIndividualAddress(USHORT vpid, void* address);
PFN_NUMBER UtilPfnFromPa(ULONG64 pa);
void* UtilVaFromPfn(PFN_NUMBER pfn);
static const ULONG kHyperPlatformCommonPoolTag = 'PpyH';

template <typename T>
constexpr bool UtilIsInBounds(_In_ const T& value, _In_ const T& min,
	_In_ const T& max) {
	return (min <= value) && (value <= max);
}

struct PhysicalMemoryRun {
	ULONG_PTR base_page;   //!< A base address / PAGE_SIZE (ie, 0x1 for 0x1000)
	ULONG_PTR page_count;  //!< A number of pages
};

struct PhysicalMemoryDescriptor {
	PFN_COUNT number_of_runs;    //!< A number of PhysicalMemoryDescriptor::run
	PFN_NUMBER number_of_pages;  //!< A physical memory size in pages
	PhysicalMemoryRun run[1];    //!< ranges of addresses
};

const PhysicalMemoryDescriptor* UtilGetPhysicalMemoryRanges();
NTSTATUS UtilInitialization();

VmxStatus UtilInveptGlobal();
// BugCheck

enum class HyperPlatformBugCheck : ULONG {
	kUnspecified,                    //!< An unspecified bug occurred
	kUnexpectedVmExit,               //!< An unexpected VM-exit occurred
	kTripleFaultVmExit,              //!< A triple fault VM-exit occurred
	kExhaustedPreallocatedEntries,   //!< All pre-allocated entries are used
	kCriticalVmxInstructionFailure,  //!< VMRESUME or VMXOFF has failed
	kEptMisconfigVmExit,             //!< EPT misconfiguration VM-exit occurred
	kCritialPoolAllocationFailure,   //!< Critical pool allocation failed
};

/// Sets a break point that works only when a debugger is present
#if !defined(HYPERPLATFORM_COMMON_DBG_BREAK)
#define HYPERPLATFORM_COMMON_DBG_BREAK() \
  if (KD_DEBUGGER_NOT_PRESENT) {         \
  } else {                               \
    __debugbreak();                      \
  }                                      \
  reinterpret_cast<void*>(0)
#endif

#if !defined(HYPERPLATFORM_COMMON_BUG_CHECK)
#define HYPERPLATFORM_COMMON_BUG_CHECK(hp_bug_check_code, param1, param2,    \
                                       param3)                               \
  HYPERPLATFORM_COMMON_DBG_BREAK();                                          \
  const HyperPlatformBugCheck code = (hp_bug_check_code);                    \
  __pragma(warning(push))                                                    \
  __pragma(warning(disable: __WARNING_USE_OTHER_FUNCTION))                   \
  KeBugCheckEx(MANUALLY_INITIATED_CRASH, static_cast<ULONG>(code), (param1), \
               (param2), (param3))                                           \
  __pragma(warning(pop))
#endif