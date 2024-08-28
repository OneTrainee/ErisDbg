#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include "vm.h"
#include "asm.h"
#include "Log.h"
#include "UtilsVT.h"
#include "VmxDefinition.h"
#include "NtExportFunction.h"

struct ProcessorData g_ProcessorData;


static BOOLEAN CheckVtAvailable() {

	// 23.6 DISCOVERING SUPPORT FOR VMX
	// If CPUID.1:ECX.VMX[bit 5] = 1, then VMX operation is supported
	int cpu_info[4];
	__cpuid(cpu_info, 1);
	const CpuFeaturesEcx cpu_feature_ecx = {
		static_cast<ULONG_PTR>(cpu_info[2])
	};
	if (!cpu_feature_ecx.fields.vmx) {
		HYPERPLATFORM_LOG_ERROR("Current cpu does not support vt, cuz cpu_feature_ecx.fields.vmx is 0");
		return FALSE;
	}

	// A.1 BASIC VMX INFORMATION
	// all processors that support VMX operation indicate the write-back type
	const Ia32VmxBasicMsr vmx_basic_msr = { UtilReadMsr64(Msr::kIa32VmxBasic) };
	if (static_cast<memory_type>(vmx_basic_msr.fields.memory_type)
		!= memory_type::kWriteBack) {
		HYPERPLATFORM_LOG_ERROR("The CPU does not support WriteBack type memory, unable to launch VMX.");
		return FALSE;
	}

	// 23.7 ENABLING AND ENTERING VMX OPERATION
	// Bit 0 is the lock bit. If this bit is clear, VMXON causes a general-protection exception. 
	// If the lock bit is set, WRMSR to this MSR causes a general - protection exception
	// the MSR cannot be modified until a power-up reset condition
	Ia32FeatureControlMsr vmx_feature_control = { UtilReadMsr64(Msr::kIa32FeatureControl) };
	if (vmx_feature_control.fields.lock == 0) {
		vmx_feature_control.fields.lock = 1;
		UtilWriteMsr64(Msr::kIa32FeatureControl, vmx_feature_control.all);
		const Ia32FeatureControlMsr vmx_feature_control_2 = { UtilReadMsr64(Msr::kIa32FeatureControl) };
		if (vmx_feature_control.fields.lock == 0) {
			HYPERPLATFORM_LOG_ERROR("Failed to modify the lock bit of VMXFeatureControl.");
			return FALSE;
		}
		HYPERPLATFORM_LOG_INFO("Successfully modified the lock bit of VMXFeatureControl");
	}

	// 23.7 ENABLING AND ENTERING VMX OPERATION
	// Bit 2 enables VMXON outside SMX operation.
	if (vmx_feature_control.fields.enable_vmxon != 1) {
		HYPERPLATFORM_LOG_ERROR("The current CPU does not support the VMXON instruction.");
		return FALSE;
	}

	return TRUE;
}

BOOLEAN InitVCPU(VCPU& vcpu) {

	PHYSICAL_ADDRESS physical_max = { MAXULONG64 };
	vcpu.pvmxon = MmAllocateContiguousMemory(PAGE_SIZE, physical_max);
	if (!vcpu.pvmxon) {
		return FALSE;
	}

	vcpu.pvmcs = MmAllocateContiguousMemory(PAGE_SIZE, physical_max);
	if (!vcpu.pvmcs) {
		MmFreeContiguousMemory(vcpu.pvmxon);
		return FALSE;
	}

	vcpu.p_host_stack = MmAllocateContiguousMemory(HOST_STACK_SIZE, physical_max);
	if (!vcpu.p_host_stack) {
		MmFreeContiguousMemory(vcpu.pvmcs);
		MmFreeContiguousMemory(vcpu.pvmxon);
		return FALSE;
	}


	RtlZeroMemory(vcpu.pvmxon, PAGE_SIZE);
	RtlZeroMemory(vcpu.pvmcs, PAGE_SIZE);
	RtlZeroMemory(vcpu.p_host_stack, HOST_STACK_SIZE);

	return TRUE;
}

BOOLEAN ExecuteVMXON(VCPU& vcpu) {

	// 31.5 VMM SETUP & TEAR DOWN
	// Ensure the current processor operating mode meets the required CR0 fixed bits (CR0.PE = 1, CR0.PG = 1). 
	// Other required CR0 fixed bits can be detected through the IA32_VMX_CR0_FIXED0 and IA32_VMX_CR0_FIXED1 MSRs.
	Cr0 cr0 = { __readcr0() };
	const Cr0 cr0_fixed_0 = { UtilReadMsr64(Msr::kIa32VmxCr0Fixed0) };
	const Cr0 cr0_fixed_1 = { UtilReadMsr64(Msr::kIa32VmxCr0Fixed1) };
	cr0.all &= cr0_fixed_1.all;
	cr0.all |= cr0_fixed_0.all;
	__writecr0(cr0.all);

	// 31.5 VMM SETUP & TEAR DOWN
	// Enable VMX operation by setting CR4.VMXE = 1. Ensure the resultant CR4 value supports all the CR4 fixed bits
	// 	reported in the IA32_VMX_CR4_FIXED0 and IA32_VMX_CR4_FIXED1 MSRs.
	Cr4 cr4 = { __readcr4() };
	const Cr4 cr4_fixed_0 = { UtilReadMsr64(Msr::kIa32VmxCr4Fixed0) };
	const Cr4 cr4_fixed_1 = { UtilReadMsr64(Msr::kIa32VmxCr4Fixed1) };
	cr4.all &= cr4_fixed_1.all;
	cr4.all |= cr4_fixed_0.all;
	__writecr4(cr4.all);

	// 31.5 VMM SETUP & TEAR DOWN
	// Initialize the version identifier in the VMXON region (the first 31 bits) with the VMCS revision identifier reported 
	// by capability MSRs.Clear bit 31 of the first 4 bytes of the VMXON region.
	//
	// 24.11.5 VMXON Region
	// Before executing VMXON, software should write the VMCS revision identifier (see Section 24.2) to the VMXON region.
	const Ia32VmxBasicMsr vmx_basic_msr = { UtilReadMsr64(Msr::kIa32VmxBasic) };
	*reinterpret_cast<unsigned int*>(vcpu.pvmxon) = vmx_basic_msr.fields.revision_identifier;

	// Execute VMXON with the physical address of the VMXON region as the operand
	auto vmxon_region_pa = UtilPaFromVa(vcpu.pvmxon);
	if (__vmx_on(&vmxon_region_pa)) {
		HYPERPLATFORM_LOG_ERROR("Failed to execute the __vmx_on instruction.");
		return FALSE;
	}
	return TRUE;
}

BOOLEAN InitVMCS(VCPU& vcpu) {
 
	// 31.6 PREPARATION AND LAUNCHING A VIRTUAL MACHINE
	// Initialize the version identifier in the VMCS (first 31 bits) with the VMCS revision identifier reported by the VMX 
	// capability MSR IA32_VMX_BASIC.Clear bit 31 of the first 4 bytes of the VMCS region.
	const Ia32VmxBasicMsr vmx_basic_msr = { UtilReadMsr64(Msr::kIa32VmxBasic) };
	*reinterpret_cast<unsigned int*>(vcpu.pvmcs) = vmx_basic_msr.fields.revision_identifier;

	// 31.6 PREPARATION AND LAUNCHING A VIRTUAL MACHINE
	// Execute the VMCLEAR instruction by supplying the guest-VMCS address.
	auto vmcs_region_pa = UtilPaFromVa(vcpu.pvmcs);
	if (__vmx_vmclear(&vmcs_region_pa)) {
		return FALSE;
	}

	// 31.6 PREPARATION AND LAUNCHING A VIRTUAL MACHINE
	// Execute the VMPTRLD instruction by supplying the guest-VMCS address
	if (__vmx_vmptrld(&vmcs_region_pa)) {
		return FALSE;
	}

	// The launch state of current VMCS is "clear"
	return TRUE;
}


ULONG VmxGetSegmentAccessRight(USHORT segment_selector) {

	VmxRegmentDescriptorAccessRight access_right = { 0 };
	if (segment_selector) {
		const SegmentSelector ss = { segment_selector };
		ULONG_PTR native_access_right = AsmLoadAccessRightsByte(ss.all);
		native_access_right >>= 8;
		access_right.all = (ULONG)(native_access_right);
		access_right.fields.reserved1 = 0;
		access_right.fields.reserved2 = 0;
		access_right.fields.unusable = FALSE;
	}
	else {
		access_right.fields.unusable = TRUE;
	}
	return access_right.all;
}

ULONG_PTR VmpGetSegmentBaseByDescriptor(const SegmentDescriptor* segment_descriptor) {

	// Calculate a 32bit base address
	const ULONG_PTR base_high = { segment_descriptor->fields.base_high << (6 * 4) };
	const ULONG_PTR base_middle = { segment_descriptor->fields.base_mid << (4 * 4) };
	const ULONG_PTR base_low = { segment_descriptor->fields.base_low };

	ULONG_PTR base = (base_high | base_middle | base_low) & MAXULONG;
	// Get upper 32bit of the base address if needed
	if (!segment_descriptor->fields.system) {
		SegmentDesctiptorX64* desc64 = (SegmentDesctiptorX64*)(segment_descriptor);
		ULONG64 base_upper32 = desc64->base_upper32;
		base |= (base_upper32 << 32);
	}
	return base;
}

SegmentDescriptor* VmpGetSegmentDescriptor(ULONG_PTR descriptor_table_base, USHORT segment_selector) {

	const SegmentSelector ss = { segment_selector };
	return (SegmentDescriptor*)(
		descriptor_table_base + ss.fields.index * sizeof(SegmentDescriptor));
}

ULONG_PTR VmpGetSegmentBase(
	ULONG_PTR gdt_base, USHORT segment_selector) {

	SegmentSelector ss = { segment_selector };
	if (!ss.all) {
		return 0;
	}

	if (ss.fields.ti) {
		SegmentDescriptor* local_segment_descriptor =
			VmpGetSegmentDescriptor(gdt_base, AsmReadLDTR());
		ULONG_PTR  ldt_base =
			VmpGetSegmentBaseByDescriptor(local_segment_descriptor);


		SegmentDescriptor* segment_descriptor =
			VmpGetSegmentDescriptor(ldt_base, segment_selector);
		return VmpGetSegmentBaseByDescriptor(segment_descriptor);
	}
	else {
		SegmentDescriptor* segment_descriptor =
			VmpGetSegmentDescriptor(gdt_base, segment_selector);
		return VmpGetSegmentBaseByDescriptor(segment_descriptor);
	}
}

static ULONG VmxAdjustControlValue(
	Msr msr, ULONG requested_value) {

	LARGE_INTEGER msr_value = {};
	msr_value.QuadPart = UtilReadMsr64(msr);
	auto adjusted_value = requested_value;

	// bit == 0 in high word ==> must be zero
	adjusted_value &= msr_value.HighPart;
	// bit == 1 in low word  ==> must be one
	adjusted_value |= msr_value.LowPart;
	return adjusted_value;
}

BOOLEAN SetupVMCS(PVOID guestStack, PVOID guestResumeRip) {

	const auto cpu_number = KeGetCurrentProcessorIndex();

	auto& vcpu = g_ProcessorData.vcpus[cpu_number];

	// 24.6 VM-EXECUTION CONTROL FIELDS
	Ia32VmxBasicMsr vmx_basic_msr = { UtilReadMsr64(Msr::kIa32VmxBasic) };
	const auto use_true_msrs = vmx_basic_msr.fields.vmx_capability_hint;

	// 24.6.1 Pin-Based VM-Execution Controls
	VmxPinBasedControls vmx_pin_based_control = { 0 };
	vmx_pin_based_control = { VmxAdjustControlValue(
		(use_true_msrs) ? Msr::kIa32VmxTruePinbasedCtls : Msr::kIa32VmxPinbasedCtls, vmx_pin_based_control.all)
	};
	UtilVmWrite(VmcsField::kPinBasedVmExecControl, vmx_pin_based_control.all);

	// 24.6.2 Processor-Based VM-Execution Controls
	VmxProcessorBasedControls vmx_proc_based_control = { 0 };
	vmx_proc_based_control.fields.use_msr_bitmaps = TRUE; // ʹ��MSR��bitmap����������MSR�������VM-Exit�¼�
	vmx_proc_based_control.fields.activate_secondary_control = TRUE; // ʹ�� secondary_control ��
	vmx_proc_based_control = { VmxAdjustControlValue(
		(use_true_msrs) ? Msr::kIa32VmxTrueProcBasedCtls : Msr::kIa32VmxProcBasedCtls, vmx_proc_based_control.all)
	};
	UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vmx_proc_based_control.all);

	// 24.6.2 Processor-Based VM-Execution Controls
	VmxSecondaryProcessorBasedControls vmx_sec_based_control = { 0 };
	vmx_sec_based_control.fields.enable_rdtscp = TRUE; // For Win10 ��������ã�ʱ�����ز��������invalid-opcode�쳣
	vmx_sec_based_control.fields.enable_invpcid = TRUE; // For Win10 ��������ã���Ч��������������һ��UD�쳣
	vmx_sec_based_control.fields.enable_xsaves_xstors = TRUE; // For Win10 If this control is 0, any execution of XSAVES or XRSTORS causes a #UD.

	// ��ʼ��EPT

#if 0 // EPT����
	if (VmxInitEpt()) {
		vmx_sec_based_control.fields.enable_ept = TRUE;
		vmx_sec_based_control.fields.enable_vpid = TRUE;

		ULONG number = KeGetCurrentProcessorNumberEx(NULL);
		UtilVmWrite(VmcsField::kVirtualProcessorId, number + 1);

		UtilVmWrite(VmcsField::kEptPointer, vcpu.vmxEptp.Flags);
	}
#else
	if (TRUE) {
		vmx_sec_based_control.fields.enable_ept = TRUE;
		vmx_sec_based_control.fields.enable_vpid = TRUE;

		ULONG number = KeGetCurrentProcessorNumberEx(NULL);
		UtilVmWrite(VmcsField::kVirtualProcessorId, number + 1);

		UtilVmWrite(VmcsField::kEptPointer, EptGetEptPointer(vcpu.ept_data));
	}

#endif
	vmx_sec_based_control = { VmxAdjustControlValue(Msr::kIa32VmxProcBasedCtls2, vmx_sec_based_control.all) };
	UtilVmWrite(VmcsField::kSecondaryVmExecControl, vmx_sec_based_control.all);

	// 24.8 VM-ENTRY CONTROL FIELDS
	VmxVmEntryControls vmx_vm_entry_control = { 0 };
	vmx_vm_entry_control.fields.ia32e_mode_guest = TRUE; // 64λ���������?
	vmx_vm_entry_control = { VmxAdjustControlValue(
		(use_true_msrs) ? Msr::kIa32VmxTrueEntryCtls : Msr::kIa32VmxEntryCtls, vmx_vm_entry_control.all)
	};
	UtilVmWrite(VmcsField::kVmEntryControls, vmx_vm_entry_control.all);

	// 24.7 VM-EXIT CONTROL FIELDS
	VmxVmExitControls vmx_vm_exit_control = { 0 };
	vmx_vm_exit_control.fields.host_address_space_size = TRUE;  // This control must be 0 on processors that do not support Intel 64 architecture.
	vmx_vm_exit_control = { VmxAdjustControlValue(
	(use_true_msrs) ? Msr::kIa32VmxTrueExitCtls : Msr::kIa32VmxExitCtls, vmx_vm_exit_control.all)
	};
	UtilVmWrite(VmcsField::kVmExitControls, vmx_vm_exit_control.all);

	// 24.6.6 Guest/Host Masks and Read Shadows for CR0 and CR4
	Cr0 cr0_mask = {}; // guest��cr0����ȫ����Ȩ��������Щλ���ᵼ��VM-Exit�¼�
						// ��������?����ô���guest���õ���cr0_shadow��ͬ���ᵼ��VM-Exit�¼�
	Cr0 cr0_shadow = { __readcr0() }; // guest���Զ�ȡcr0ʱ�������ȷ���?
	Cr4 cr4_mask = {};
	Cr4 cr4_shadow = { __readcr4() };
	UtilVmWrite(VmcsField::kCr0GuestHostMask, cr0_mask.all);
	UtilVmWrite(VmcsField::kCr4GuestHostMask, cr4_mask.all);
	UtilVmWrite(VmcsField::kCr0ReadShadow, cr0_shadow.all);
	UtilVmWrite(VmcsField::kCr4ReadShadow, cr4_shadow.all);

	// 24.6.9 MSR-Bitmap Address
	// ����bitmap�����ǲ������κ���Ϣ
	RtlZeroMemory(g_ProcessorData.processorSharedData.msrBitMap, PAGE_SIZE);
	UtilVmWrite(VmcsField::kMsrBitmap, UtilPaFromVa(g_ProcessorData.processorSharedData.msrBitMap));

	// 24.6.3 Exception Bitmap

	// ����Bitmap������int3�ϵ㣬����ע��
	// NOTE: Comment in any of those as needed
	const auto exception_bitmap =
		1 << InterruptionVector::kBreakpointException |
		1 << InterruptionVector::kDebugException |
		// 1 << InterruptionVector::kGeneralProtectionException |
		// 1 << InterruptionVector::kPageFaultException |
		0;
	UtilVmWrite(VmcsField::kExceptionBitmap, exception_bitmap);

	Gdtr gdtr = {};
	_sgdt(&gdtr);
	Idtr idtr = {};
	__sidt(&idtr);

	// ���Guest��
	UtilVmWrite(VmcsField::kGuestEsSelector, AsmReadES());
	UtilVmWrite(VmcsField::kGuestCsSelector, AsmReadCS());
	UtilVmWrite(VmcsField::kGuestSsSelector, AsmReadSS());
	UtilVmWrite(VmcsField::kGuestDsSelector, AsmReadDS());
	UtilVmWrite(VmcsField::kGuestFsSelector, AsmReadFS());
	UtilVmWrite(VmcsField::kGuestGsSelector, AsmReadGS());
	UtilVmWrite(VmcsField::kGuestLdtrSelector, AsmReadLDTR()); // �ֲ���������
	UtilVmWrite(VmcsField::kGuestTrSelector, AsmReadTR());	// ����Ĵ���?

	UtilVmWrite(VmcsField::kVmcsLinkPointer, MAXULONG64);
	UtilVmWrite(VmcsField::kGuestIa32Debugctl, UtilReadMsr64(Msr::kIa32Debugctl));


	UtilVmWrite(VmcsField::kGuestEsLimit, GetSegmentLimit(AsmReadES()));
	UtilVmWrite(VmcsField::kGuestCsLimit, GetSegmentLimit(AsmReadCS()));
	UtilVmWrite(VmcsField::kGuestSsLimit, GetSegmentLimit(AsmReadSS()));
	UtilVmWrite(VmcsField::kGuestDsLimit, GetSegmentLimit(AsmReadDS()));
	UtilVmWrite(VmcsField::kGuestFsLimit, GetSegmentLimit(AsmReadFS()));
	UtilVmWrite(VmcsField::kGuestGsLimit, GetSegmentLimit(AsmReadGS()));
	UtilVmWrite(VmcsField::kGuestLdtrLimit, GetSegmentLimit(AsmReadLDTR()));
	UtilVmWrite(VmcsField::kGuestTrLimit, GetSegmentLimit(AsmReadTR()));
	UtilVmWrite(VmcsField::kGuestGdtrLimit, gdtr.limit);
	UtilVmWrite(VmcsField::kGuestIdtrLimit, idtr.limit);

	UtilVmWrite(VmcsField::kGuestEsArBytes, VmxGetSegmentAccessRight(AsmReadES()));
	UtilVmWrite(VmcsField::kGuestCsArBytes, VmxGetSegmentAccessRight(AsmReadCS()));
	UtilVmWrite(VmcsField::kGuestSsArBytes, VmxGetSegmentAccessRight(AsmReadSS()));
	UtilVmWrite(VmcsField::kGuestDsArBytes, VmxGetSegmentAccessRight(AsmReadDS()));
	UtilVmWrite(VmcsField::kGuestFsArBytes, VmxGetSegmentAccessRight(AsmReadFS()));
	UtilVmWrite(VmcsField::kGuestGsArBytes, VmxGetSegmentAccessRight(AsmReadGS()));
	UtilVmWrite(VmcsField::kGuestLdtrArBytes, VmxGetSegmentAccessRight(AsmReadLDTR()));
	UtilVmWrite(VmcsField::kGuestTrArBytes, VmxGetSegmentAccessRight(AsmReadTR()));
	UtilVmWrite(VmcsField::kGuestSysenterCs, UtilReadMsr64(Msr::kIa32SysenterCs));


	UtilVmWrite(VmcsField::kGuestCr0, __readcr0());
	UtilVmWrite(VmcsField::kGuestCr3, __readcr3());
	UtilVmWrite(VmcsField::kGuestCr4, __readcr4());

	UtilVmWrite(VmcsField::kGuestEsBase, 0);
	UtilVmWrite(VmcsField::kGuestCsBase, 0);
	UtilVmWrite(VmcsField::kGuestSsBase, 0);
	UtilVmWrite(VmcsField::kGuestDsBase, 0);
	UtilVmWrite(VmcsField::kGuestFsBase, UtilReadMsr64(Msr::kIa32FsBase));
	UtilVmWrite(VmcsField::kGuestGsBase, UtilReadMsr64(Msr::kIa32GsBase));
	UtilVmWrite(VmcsField::kGuestLdtrBase, VmpGetSegmentBase(gdtr.base, AsmReadLDTR()));
	UtilVmWrite(VmcsField::kGuestTrBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
	UtilVmWrite(VmcsField::kGuestGdtrBase, gdtr.base);
	UtilVmWrite(VmcsField::kGuestIdtrBase, idtr.base);

	UtilVmWrite(VmcsField::kGuestDr7, __readdr(7));
	UtilVmWrite(VmcsField::kGuestRsp, (ULONG64)guestStack);
	UtilVmWrite(VmcsField::kGuestRip, (ULONG64)guestResumeRip);
	UtilVmWrite(VmcsField::kGuestRflags, __readeflags());
	UtilVmWrite(VmcsField::kGuestSysenterEsp, UtilReadMsr64(Msr::kIa32SysenterEsp));
	UtilVmWrite(VmcsField::kGuestSysenterEip, UtilReadMsr64(Msr::kIa32SysenterEip));

	// ��дHost��
	UtilVmWrite(VmcsField::kHostEsSelector, AsmReadES() & 0xf8);
	UtilVmWrite(VmcsField::kHostCsSelector, AsmReadCS() & 0xf8);
	UtilVmWrite(VmcsField::kHostSsSelector, AsmReadSS() & 0xf8);
	UtilVmWrite(VmcsField::kHostDsSelector, AsmReadDS() & 0xf8);
	UtilVmWrite(VmcsField::kHostFsSelector, AsmReadFS() & 0xf8);
	UtilVmWrite(VmcsField::kHostGsSelector, AsmReadGS() & 0xf8);
	UtilVmWrite(VmcsField::kHostTrSelector, AsmReadTR() & 0xf8);
	UtilVmWrite(VmcsField::kHostIa32SysenterCs, UtilReadMsr64(Msr::kIa32SysenterCs));
	UtilVmWrite(VmcsField::kHostCr0, __readcr0());
	UtilVmWrite(VmcsField::kHostCr3, __readcr3());
	UtilVmWrite(VmcsField::kHostCr4, __readcr4());
	UtilVmWrite(VmcsField::kHostFsBase, UtilReadMsr64(Msr::kIa32FsBase));
	UtilVmWrite(VmcsField::kHostGsBase, UtilReadMsr64(Msr::kIa32GsBase));
	UtilVmWrite(VmcsField::kHostTrBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
	UtilVmWrite(VmcsField::kHostGdtrBase, gdtr.base);
	UtilVmWrite(VmcsField::kHostIdtrBase, idtr.base);
	UtilVmWrite(VmcsField::kHostIa32SysenterEsp, UtilReadMsr64(Msr::kIa32SysenterEsp));
	UtilVmWrite(VmcsField::kHostIa32SysenterEip, UtilReadMsr64(Msr::kIa32SysenterEip));

	// AsmVmmEntryPoint
	UtilVmWrite(VmcsField::kHostRsp, (ULONG64)vcpu.p_host_stack + HOST_STACK_SIZE - PAGE_SIZE);
	UtilVmWrite(VmcsField::kHostRip, reinterpret_cast<ULONG_PTR>(AsmVmmEntryPoint));

	// DbgBreakPoint();
	__vmx_vmlaunch();

	//���ִ�е�����?˵��ʧ����
	const auto errorCode = UtilVmRead(VmcsField::kVmInstructionError);
	DbgPrint("[*] VmLaunchʧ��!������: %d", errorCode);

	return TRUE;
}

VOID LoadVtForEachProcessor(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	const auto cpu_number = KeGetCurrentProcessorNumber();
	HYPERPLATFORM_LOG_INFO("current cpu number : %d", cpu_number);

	auto& vcpu = g_ProcessorData.vcpus[cpu_number];
	
	if (!CheckVtAvailable()) {
		HYPERPLATFORM_LOG_ERROR("Failed to enable VT; VT is currently unavailable.");
		return;
	}

	if (!InitVCPU(vcpu)) {
		HYPERPLATFORM_LOG_ERROR("Failed to enable VT; VCPU initialization failed.");
		return;
	}

	vcpu.ept_data = EptInitialization();
	if (!vcpu.ept_data) {
		HYPERPLATFORM_LOG_ERROR("Failed to enable VT; Ept Initialization failed.");
		return;
	}

	if (!ExecuteVMXON(vcpu)) {
		HYPERPLATFORM_LOG_ERROR("Failed to enable VT; VMXON execution failed.");
		return;
	}

	if (!InitVMCS(vcpu)) {
		HYPERPLATFORM_LOG_ERROR("Failed to enable VT; VMCS initialization failed.");
		return;
	}

	
	AsmVmxLaunch(SetupVMCS);

	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);

}

VOID LoadVtForEachProcessor_2()
{

	const auto cpu_number = KeGetCurrentProcessorNumber();
	HYPERPLATFORM_LOG_INFO("current cpu number : %d", cpu_number);

	auto& vcpu = g_ProcessorData.vcpus[cpu_number];

	if (!CheckVtAvailable()) {
		HYPERPLATFORM_LOG_ERROR("Failed to enable VT; VT is currently unavailable.");
		return;
	}

	if (!InitVCPU(vcpu)) {
		HYPERPLATFORM_LOG_ERROR("Failed to enable VT; VCPU initialization failed.");
		return;
	}

	vcpu.ept_data = EptInitialization();
	if (!vcpu.ept_data) {
		HYPERPLATFORM_LOG_ERROR("Failed to enable VT; Ept Initialization failed.");
		return;
	}

	if (!ExecuteVMXON(vcpu)) {
		HYPERPLATFORM_LOG_ERROR("Failed to enable VT; VMXON execution failed.");
		return;
	}

	if (!InitVMCS(vcpu)) {
		HYPERPLATFORM_LOG_ERROR("Failed to enable VT; VMCS initialization failed.");
		return;
	}


	AsmVmxLaunch(SetupVMCS);

}

BOOLEAN InitProcessorSharedData() {

	PHYSICAL_ADDRESS physical_max = { MAXULONG64 };
	g_ProcessorData.processorSharedData.msrBitMap = MmAllocateContiguousMemory(PAGE_SIZE, physical_max);
	if (!g_ProcessorData.processorSharedData.msrBitMap) {
		HYPERPLATFORM_LOG_ERROR("Failed to allocate memory for the Msr Bitmap.");
		return FALSE;
	}

	return TRUE;
}

NTSTATUS LoadVT() {

	BOOLEAN bSuccess = FALSE;
	// DbgBreakPoint();
	EptInitializeMtrrEntries();
	bSuccess = InitProcessorSharedData();
	if (!bSuccess) {
		HYPERPLATFORM_LOG_INFO("Failed to Init ProcessorSharedData");
		return STATUS_UNSUCCESSFUL;
	}
	NTSTATUS status = UtilInitialization();
	if (!NT_SUCCESS(status)) {
		HYPERPLATFORM_LOG_INFO("Failed to Init Util");
		return status;
	}
	KeGenericCallDpc(LoadVtForEachProcessor, NULL);
	return STATUS_SUCCESS;
}

static VOID UnloadVtForEachProcessor(
	_In_ struct _KDPC* Dpc,
	_In_opt_ PVOID DeferredContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2)
{
	UNREFERENCED_PARAMETER(Dpc);
	UNREFERENCED_PARAMETER(DeferredContext);

	const auto cpu_number = KeGetCurrentProcessorNumber();
	//__vmx_off();
	AsmVmxCall(CallExitVT, NULL);

	Cr4 cr4 = { __readcr4() };
	cr4.fields.vmxe = false;
	__writecr4(cr4.all);

	auto& vcpu = g_ProcessorData.vcpus[cpu_number];
	MmFreeContiguousMemory(vcpu.pvmcs);
	MmFreeContiguousMemory(vcpu.pvmxon);
	MmFreeContiguousMemory(vcpu.p_host_stack);
	EptTermination(vcpu.ept_data);
	KeSignalCallDpcSynchronize(SystemArgument2);
	KeSignalCallDpcDone(SystemArgument1);
}

VOID UnloadVT() {
	KeGenericCallDpc(UnloadVtForEachProcessor, NULL);
	MmFreeContiguousMemory(g_ProcessorData.processorSharedData.msrBitMap);
}