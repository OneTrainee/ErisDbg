#include <ntifs.h>
#include <intrin.h>
#include "Log.h"
#include "ia32_type.h"
#include "UtilsVT.h"
#include "asm.h"

static PhysicalMemoryDescriptor* UtilpBuildPhysicalMemoryRanges();

ULONG64 UtilReadMsr64(Msr msr) {
	return __readmsr(static_cast<unsigned long>(msr));
}

void UtilWriteMsr64(Msr msr, ULONG64 value) {
	__writemsr(static_cast<unsigned long>(msr), value);
}

ULONG64 UtilPaFromVa(void* va) {
	const auto pa = MmGetPhysicalAddress(va);
	return pa.QuadPart;
}

VmxStatus UtilVmWrite(VmcsField field,
	ULONG64 field_value) {
	return static_cast<VmxStatus>(
		__vmx_vmwrite(static_cast<size_t>(field), field_value));
}

ULONG_PTR UtilVmRead(VmcsField field) {
	size_t field_value = 0;
	const auto vmx_status = static_cast<VmxStatus>(
		__vmx_vmread(static_cast<size_t>(field), &field_value));
	return field_value;
}

VmxStatus UtilInveptGlobal() {
    
    InvEptDescriptor desc = {};

    Asminvept((ULONG)InvEptType::kGlobalInvalidation, (ULONG64)&desc);
   
    return VmxStatus::kOk;
}

VmxStatus UtilInvvpidIndividualAddress(USHORT vpid, void* address) {
	InvVpidDescriptor desc = {};
	desc.vpid = vpid;
	desc.linear_address = reinterpret_cast<ULONG64>(address);
	return static_cast<VmxStatus>(
		AsmInvvpid(InvVpidType::kIndividualAddressInvalidation, &desc));
}

PFN_NUMBER UtilPfnFromPa(ULONG64 pa) {
	return static_cast<PFN_NUMBER>(pa >> PAGE_SHIFT);
}

// -----------------------------------



static PhysicalMemoryDescriptor* g_utilp_physical_memory_ranges;

// Initializes the physical memory ranges
static NTSTATUS UtilpInitializePhysicalMemoryRanges() {
    PAGED_CODE();

    const auto ranges = UtilpBuildPhysicalMemoryRanges();
    if (!ranges) {
        return STATUS_UNSUCCESSFUL;
    }

    g_utilp_physical_memory_ranges = ranges;

    for (auto i = 0ul; i < ranges->number_of_runs; ++i) {
        auto base_addr =
            static_cast<ULONG64>(ranges->run[i].base_page) * PAGE_SIZE;
        HYPERPLATFORM_LOG_DEBUG("Physical Memory Range: %016llx - %016llx",
            base_addr,
            base_addr + ranges->run[i].page_count * PAGE_SIZE);
    }

    auto pm_size =
        static_cast<ULONG64>(ranges->number_of_pages) * PAGE_SIZE;
    HYPERPLATFORM_LOG_DEBUG("Physical Memory Total: %llu KB", pm_size / 1024);

    return STATUS_SUCCESS;
}

// Builds the physical memory ranges
static PhysicalMemoryDescriptor*
UtilpBuildPhysicalMemoryRanges() {
    PAGED_CODE();

    const auto pm_ranges = MmGetPhysicalMemoryRanges();
    if (!pm_ranges) {
        return nullptr;
    }

    PFN_COUNT number_of_runs = 0;
    PFN_NUMBER number_of_pages = 0;
    for (/**/; /**/; ++number_of_runs) {
        const auto range = &pm_ranges[number_of_runs];
        if (!range->BaseAddress.QuadPart && !range->NumberOfBytes.QuadPart) {
            break;
        }
        number_of_pages +=
            static_cast<PFN_NUMBER>(BYTES_TO_PAGES(range->NumberOfBytes.QuadPart));
    }
    if (number_of_runs == 0) {
        ExFreePoolWithTag(pm_ranges, 'hPmM');
        return nullptr;
    }

    const auto memory_block_size =
        sizeof(PhysicalMemoryDescriptor) +
        sizeof(PhysicalMemoryRun) * (number_of_runs - 1);
    const auto pm_block =
        reinterpret_cast<PhysicalMemoryDescriptor*>(ExAllocatePoolWithTag(
            NonPagedPool, memory_block_size, kHyperPlatformCommonPoolTag));
    if (!pm_block) {
        ExFreePoolWithTag(pm_ranges, 'hPmM');
        return nullptr;
    }
    RtlZeroMemory(pm_block, memory_block_size);

    pm_block->number_of_runs = number_of_runs;
    pm_block->number_of_pages = number_of_pages;

    for (auto run_index = 0ul; run_index < number_of_runs; run_index++) {
        auto current_run = &pm_block->run[run_index];
        auto current_block = &pm_ranges[run_index];
        current_run->base_page = static_cast<ULONG_PTR>(
            UtilPfnFromPa(current_block->BaseAddress.QuadPart));
        current_run->page_count = static_cast<ULONG_PTR>(
            BYTES_TO_PAGES(current_block->NumberOfBytes.QuadPart));
    }

    ExFreePoolWithTag(pm_ranges, 'hPmM');
    return pm_block;
}

// Returns the physical memory ranges
/*_Use_decl_annotations_*/ const PhysicalMemoryDescriptor*
UtilGetPhysicalMemoryRanges() {
    return g_utilp_physical_memory_ranges;
}

ULONG64 UtilPaFromPfn(PFN_NUMBER pfn) {
    return static_cast<ULONG64>(pfn) << PAGE_SHIFT;
}

void* UtilVaFromPa(ULONG64 pa) {
    PHYSICAL_ADDRESS pa2 = {};
    pa2.QuadPart = pa;
    return MmGetVirtualForPhysical(pa2);
}


void* UtilVaFromPfn(PFN_NUMBER pfn) {
    return UtilVaFromPa(UtilPaFromPfn(pfn));
}

NTSTATUS UtilInitialization() {
    NTSTATUS status = UtilpInitializePhysicalMemoryRanges();
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return STATUS_SUCCESS;
}