#include "ia32_type.h"
#include "UtilsVT.h"
#include "Log.h"
#include "asm.h"
#include "ept.h"
#include "PageHook.h"
#include "vm.h"
#include <intrin.h>

#define EPML4_INDEX(__ADDRESS__)		((__ADDRESS__ >> 39) & 0x1FF)
#define EPDPTE_INDEX(__ADDRESS__)		((__ADDRESS__ >> 30) & 0x1FF)
#define EPDE_INDEX(__ADDRESS__)			((__ADDRESS__ >> 21) & 0x1FF)
#define EPTE_INDEX(__ADDRESS__)			((__ADDRESS__ >> 12) & 0x1FF)

#define ACCESS_EPT_READ		1
#define ACCESS_EPT_WRITE	2
#define ACCESS_EPT_EXECUTE	4

BOOLEAN VmxIsSupprtEpt() {
	// A.10 VPID AND EPT CAPABILITIES
	// The IA32_VMX_EPT_VPID_CAP MSR (index 48CH) reports information about the capabilities of the logical 
	// processor with regard to virtual - processor identifiers(VPIDs, Section 28.1) and extended page tables(EPT, Section 28.2) :
	// 
	Ia32VmxEptVpidCapMsr capability = { UtilReadMsr64(Msr::kIa32VmxEptVpidCap) };
	if (!capability.fields.support_page_walk_length4 ||
		!capability.fields.support_write_back_memory_type ||
		!capability.fields.support_invept ||
		!capability.fields.support_single_context_invept ||
		!capability.fields.support_all_context_invept ||
		!capability.fields.support_invvpid ||
		!capability.fields.support_individual_address_invvpid ||
		!capability.fields.support_single_context_invvpid ||
		!capability.fields.support_all_context_invvpid ||
		!capability.fields.support_single_context_retaining_globals_invvpid) {
		return FALSE;
	}

	return TRUE;
}

BOOLEAN VmxInitEpt()
{
	if (!VmxIsSupprtEpt()) {
		HYPERPLATFORM_LOG_ERROR("当前CPU不支持EPT功能，EPT功能开启失败!");
		return FALSE;
	}

	Ia32VmxEptVpidCapMsr vmx_ept_vpid_cap_msr = { UtilReadMsr64(Msr::kIa32VmxEptVpidCap) };
	BOOLEAN is_writeback = vmx_ept_vpid_cap_msr.fields.support_write_back_memory_type;

	// 是否支持读写
	// memory_type::kWriteBack /  memory_type::kUncacheable
	ULONG64 MemoryType  = is_writeback ? 6:0;
	
	const auto current_cpu_number = KeGetCurrentProcessorNumber();
	auto vcpu = &g_ProcessorData.vcpus[current_cpu_number];

	vcpu->vmxMamgerPage = reinterpret_cast<PVMX_MAMAGER_PAGE_ENTRY>(
		ExAllocatePool(NonPagedPool, sizeof(VMX_MAMAGER_PAGE_ENTRY)));

	if (!vcpu->vmxMamgerPage) {
		HYPERPLATFORM_LOG_ERROR("vmxMamgerPage分配内存失败，EPT功能开启失败!");
		return FALSE;
	}

	vcpu->vmxMamgerPage->pmlt[0].Flags = 0;
	vcpu->vmxMamgerPage->pmlt[0].ExecuteAccess = 1;
	vcpu->vmxMamgerPage->pmlt[0].ReadAccess = 1;
	vcpu->vmxMamgerPage->pmlt[0].WriteAccess = 1;
	vcpu->vmxMamgerPage->pmlt[0].PageFrameNumber = MmGetPhysicalAddress(&vcpu->vmxMamgerPage->pdptt).QuadPart / PAGE_SIZE;
	
	for (int i = 0; i < PDPTE_ENTRY_COUNT; i++)
	{
		vcpu->vmxMamgerPage->pdptt[i].Flags = 0;
		vcpu->vmxMamgerPage->pdptt[i].ExecuteAccess = 1;
		vcpu->vmxMamgerPage->pdptt[i].ReadAccess = 1;
		vcpu->vmxMamgerPage->pdptt[i].WriteAccess = 1;
		vcpu->vmxMamgerPage->pdptt[i].PageFrameNumber = MmGetPhysicalAddress(&vcpu->vmxMamgerPage->pdt[i][0]).QuadPart / PAGE_SIZE;

		for (int j = 0; j < PDE_ENTRY_COUNT; j++)
		{
			vcpu->vmxMamgerPage->pdt[i][j].Flags = 0;
			vcpu->vmxMamgerPage->pdt[i][j].ExecuteAccess = 1;
			vcpu->vmxMamgerPage->pdt[i][j].ReadAccess = 1;
			vcpu->vmxMamgerPage->pdt[i][j].WriteAccess = 1;
			vcpu->vmxMamgerPage->pdt[i][j].MemoryType = MemoryType;
			vcpu->vmxMamgerPage->pdt[i][j].LargePage = 1;
			vcpu->vmxMamgerPage->pdt[i][j].PageFrameNumber = i * 512 + j;
		}
	}

	//DbgBreakPoint();

	vcpu->vmxEptp.Flags = 0;

	vcpu->vmxEptp.MemoryType = MemoryType;

	vcpu->vmxEptp.PageWalkLength = 3;

	// (capValue >> 21) & 1;
	vcpu->vmxEptp.EnableAccessAndDirtyFlags = vmx_ept_vpid_cap_msr.fields.support_accessed_and_dirty_flag;

	vcpu->vmxEptp.PageFrameNumber = MmGetPhysicalAddress(&vcpu->vmxMamgerPage->pmlt).QuadPart / PAGE_SIZE;

	return TRUE;
}

PEPDE_2MB GetPDE2M_HPAByGPA(ULONG64 Gpa)
{
	const auto current_cpu_number = KeGetCurrentProcessorNumber();
	auto vcpu = &g_ProcessorData.vcpus[current_cpu_number];

	//EPML4INDEX
	ULONG64 pml4Index = EPML4_INDEX(Gpa);

	if (pml4Index > 0)
	{
		return NULL;
	}

	//EPDPTEINDEX
	ULONG64 pdepteIndex = EPDPTE_INDEX(Gpa);
	//PDEINDEX
	ULONG64 pdeIndex = EPDE_INDEX(Gpa);

	return &vcpu->vmxMamgerPage->pdt[pdepteIndex][pdeIndex];
}

VOID EptSplit(PEPDE_2MB pde)
{
	//我们得给切割
	PEPTE ptes = (PEPTE)ExAllocatePool(NonPagedPool, sizeof(EPTE) * 512);

	for (int i = 0; i < PTE_ENTRY_COUNT; i++)
	{
		ptes[i].Flags = 0;
		ptes[i].ExecuteAccess = 1;
		ptes[i].WriteAccess = 1;
		ptes[i].ReadAccess = 1;
		//ptes[i].MemoryType = vmxEntry->vmxEptp.MemoryType;
		ptes[i].PageFrameNumber = (pde->PageFrameNumber << 9) + i;
	}

	EPDE pde4k;
	pde4k.Flags = 0;
	pde4k.ReadAccess = 1;
	pde4k.WriteAccess = 1;
	pde4k.ExecuteAccess = 1;
	pde4k.PageFrameNumber = MmGetPhysicalAddress(ptes).QuadPart / PAGE_SIZE;

	memcpy(pde, &pde4k, sizeof(pde4k));

}

PEPTE EptGetPte(ULONG64 PfNumber)
{

	PEPDE_2MB pde = GetPDE2M_HPAByGPA(PfNumber);

	if (pde->LargePage) return NULL;

	PEPDE pde4K = (PEPDE)pde;

	ULONG64 ptePhy = pde4K->PageFrameNumber * PAGE_SIZE;

	PHYSICAL_ADDRESS ptePhyAddr = { 0 };

	ptePhyAddr.QuadPart = ptePhy;

	PEPTE ptes = (PEPTE)MmGetVirtualForPhysical(ptePhyAddr);

	ULONG64 pteindex = EPTE_INDEX(PfNumber);

	return &ptes[pteindex];
}

VOID EptHookVmCall_2(ULONG64 kernelCr3, ULONG64 CodePfNumber, ULONG64 DataPfNumber, PULONG64 isHook)
{

	ULONG64 cr3 = __readcr3();

	__writecr3(kernelCr3);

	const auto current_cpu_number = KeGetCurrentProcessorNumber();
	auto vcpu = &g_ProcessorData.vcpus[current_cpu_number];

	do
	{
		ULONG64 pfnData = DataPfNumber * PAGE_SIZE;

		ULONG64 pfnCode = CodePfNumber * PAGE_SIZE;

		PEPDE_2MB pdeData = GetPDE2M_HPAByGPA(pfnData);

		PEPDE_2MB pdeCode = GetPDE2M_HPAByGPA(pfnCode);

		if (!pdeData || !pdeCode) break;

		if (pdeData->LargePage)
		{
			EptSplit(pdeData);
		}

		if (pdeCode->LargePage)
		{
			EptSplit(pdeCode);
		}
		PEPTE pteData = EptGetPte(pfnData);
		pteData->ExecuteAccess = 0;


		*isHook = TRUE;
	} while (0);


	__writecr3(cr3);

	Asminvept(2, reinterpret_cast<ULONG64>(&vcpu->vmxEptp.Flags));
}

VOID VmxEptUpdatePage_2(ULONG Access, ULONG64 cr3, ULONG64 LinerAddr, ULONG64 guestPhyAddress)
{
	ULONG64 startPage = (LinerAddr >> 12) << 12;

	PPageHookContext context = EptGetPageHookContext(startPage, cr3, cr3);

	if (!context) return;

	PEPTE pte = EptGetPte(guestPhyAddress);

	if (!pte) return;



	if (Access == ACCESS_EPT_READ)
	{
		pte->PageFrameNumber = context->OldFunAddrPageNumber;

		pte->ReadAccess = 1;

		pte->ExecuteAccess = 0;

		pte->WriteAccess = 1;

		__invlpg(reinterpret_cast<PVOID>(LinerAddr));
	}
	else if (Access == ACCESS_EPT_EXECUTE)
	{
		pte->PageFrameNumber = context->NewAddrPageNumber;

		pte->ReadAccess = 0;

		pte->ExecuteAccess = 1;

		pte->WriteAccess = 0;

		__invlpg(reinterpret_cast<PVOID>(LinerAddr));

	}
	else if (Access == ACCESS_EPT_WRITE)
	{
		pte->PageFrameNumber = context->OldFunAddrPageNumber;

		pte->ReadAccess = 1;

		pte->ExecuteAccess = 0;

		pte->WriteAccess = 1;

		__invlpg(reinterpret_cast<PVOID>(LinerAddr));
	}
}

VOID VmxEptHandler(GpRegisters* context)
{

	// DbgBreakPoint();

	typedef union _EPTINFO
	{
		struct
		{

			ULONG64 read : 1;
			ULONG64 wrire : 1;
			ULONG64 execute : 1;

			ULONG64 readable : 1;
			ULONG64 wrireable : 1;
			ULONG64 executeable : 1;
			ULONG64 un1 : 1;
			ULONG64 vaild : 1;
			ULONG64 translation : 1;
			ULONG64 un2 : 3;
			ULONG64 NMIUnblocking : 1;
			ULONG64 un3 : 51;
		};

		ULONG64 Flags;
	} EPTINFO, * PEPTINFO;

	
	ULONG64 mrip = 0; //0x0400000 : mov eax,dword ptr ds:[0x12345678]
	ULONG64 mrsp = 0;
	ULONG64 mCr3 = 0;
	ULONG64 instLen = 0;
	ULONG64 guestLineAddress = 0;
	ULONG64 guestPhyAddress = 0;

	//__vmx_vmread(EXIT_QUALIFICATION, (PULONG64)&eptinfo); //偏移量
	//__vmx_vmread(GUEST_RSP, &mrsp);
	//__vmx_vmread(GUEST_RIP, &mrip);
	//__vmx_vmread(GUEST_CR3, &mCr3);
	//__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &instLen); // 获取指令长度
	EPTINFO eptinfo;
	eptinfo.Flags =  UtilVmRead(VmcsField::kExitQualification) ;
	mrsp = UtilVmRead(VmcsField::kGuestRsp);
	mrip = UtilVmRead(VmcsField::kGuestRip);
	mCr3 = UtilVmRead(VmcsField::kGuestCr3);
	instLen = UtilVmRead(VmcsField::kVmExitInstructionLen);

	//PVMXCPUPCB vmxEntry = VmxGetCurrentCPUPCB();
	const auto current_cpu_number = KeGetCurrentProcessorNumber();
	auto vcpu = &g_ProcessorData.vcpus[current_cpu_number];

	if (!eptinfo.vaild)
	{
		return;
	}



	//获取线性地址
	//__vmx_vmread(GUEST_LINEAR_ADDRESS, &guestLineAddress);
	guestLineAddress = UtilVmRead(VmcsField::kGuestLinearAddress);

	//获取GPA
	//__vmx_vmread(GUEST_PHYSICAL_ADDRESS, &guestPhyAddress);
	guestPhyAddress = UtilVmRead(VmcsField::kGuestPhysicalAddress);


	//GPA 转化为HPA

	if (eptinfo.read)
	{
		//读引起的异常
		VmxEptUpdatePage_2(ACCESS_EPT_READ, mCr3, guestLineAddress, guestPhyAddress);
	}


	if (eptinfo.wrire)
	{
		//写引起的异常
		VmxEptUpdatePage_2(ACCESS_EPT_WRITE, mCr3, guestLineAddress, guestPhyAddress);
	}

	if (eptinfo.execute)
	{
		//执行引起的异常
		VmxEptUpdatePage_2(ACCESS_EPT_EXECUTE, mCr3, guestLineAddress, guestPhyAddress);
	}

	Asminvept(2,reinterpret_cast<ULONG64>(&vcpu->vmxEptp.Flags));

	//__vmx_vmwrite(GUEST_RIP, mrip);
	//__vmx_vmwrite(GUEST_RSP, mrsp);

	UtilVmWrite(VmcsField::kGuestRip, mrip);
	UtilVmWrite(VmcsField::kGuestRsp, mrsp);
}