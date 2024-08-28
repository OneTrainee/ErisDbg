#include <ntifs.h>
#include <ntddk.h>
#include "Log.h"
#include "ia32_type.h"
#include "UtilsVT.h"
#include "vm.h"
#include "asm.h"
#include "VmxDefinition.h"
#include "Performance.h"
#include "PageHook.h"
#include "ept2.h"
#include <intrin.h>
#pragma warning(push)
#pragma warning(disable:4244)

void VmxAdjustGuestRip()
{
	ULONG inst_len = 0;
	ULONG_PTR rip = 0;

	rip = UtilVmRead(VmcsField::kGuestRip);
	inst_len = UtilVmRead(VmcsField::kVmExitInstructionLen);
	UtilVmWrite(VmcsField::kGuestRip, rip + inst_len);
}


void VmxPrepareOff(GpRegisters* pGuestRegisters)
{
	ULONG_PTR gdt_limit = 0;
	gdt_limit = UtilVmRead(VmcsField::kGuestGdtrLimit);

	ULONG_PTR gdt_base = 0;
	gdt_base = UtilVmRead(VmcsField::kGuestGdtrBase);

	ULONG_PTR idt_limit = 0;
	idt_limit = UtilVmRead(VmcsField::kGuestIdtrLimit);

	ULONG_PTR idt_base = 0;
	idt_base = UtilVmRead(VmcsField::kGuestIdtrBase);

	Gdtr gdtr = { (USHORT)gdt_limit, gdt_base };
	Idtr idtr = { (USHORT)idt_limit, idt_base };
	AsmWriteGDT(&gdtr);
	__lidt(&idtr);

	/*
		rip = UtilVmRead(VmcsField::kGuestRip);
	inst_len = UtilVmRead(VmcsField::kVmExitInstructionLen);
	UtilVmWrite(VmcsField::kGuestRip, rip + inst_len);
	*/
	ULONG_PTR exit_instruction_length = 0;
	exit_instruction_length = UtilVmRead(VmcsField::kVmExitInstructionLen);
	ULONG_PTR rip = 0;
	rip = UtilVmRead(VmcsField::kGuestRip);
	ULONG_PTR return_address = rip + exit_instruction_length;

	// Since the flag register is overwritten after VMXOFF, we should manually
	// indicates that VMCALL was successful by clearing those flags.
	// See: CONVENTIONS
	FlagRegister rflags = { 0 };
	rflags.all = UtilVmRead(VmcsField::kGuestRflags);

	rflags.fields.cf = FALSE;
	rflags.fields.pf = FALSE;
	rflags.fields.af = FALSE;
	rflags.fields.zf = FALSE;
	rflags.fields.sf = FALSE;
	rflags.fields.of = FALSE;
	rflags.fields.cf = FALSE;
	rflags.fields.zf = FALSE;

	// Set registers used after VMXOFF to recover the context. Volatile
	// registers must be used because those changes are reflected to the
	// guest's context after VMXOFF.
	pGuestRegisters->cx = return_address;
	pGuestRegisters->dx = UtilVmRead(VmcsField::kGuestRsp);
	pGuestRegisters->ax = rflags.all;
}

VOID VmxMsrReadWriteHandler(GpRegisters* p_guest_registers, BOOLEAN is_read)
{
	HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	const auto msr = static_cast<Msr>(p_guest_registers->cx);


	BOOLEAN transfer_to_vmcs = false;
	VmcsField vmcs_field = {};

	switch (msr) {
	case Msr::kIa32SysenterCs:
		vmcs_field = VmcsField::kGuestSysenterCs;
		transfer_to_vmcs = true;
		break;
	case Msr::kIa32SysenterEsp:
		vmcs_field = VmcsField::kGuestSysenterEsp;
		transfer_to_vmcs = true;
		break;
	case Msr::kIa32SysenterEip:
		vmcs_field = VmcsField::kGuestSysenterEip;
		transfer_to_vmcs = true;
		break;
	case Msr::kIa32Debugctl:
		vmcs_field = VmcsField::kGuestIa32Debugctl;
		transfer_to_vmcs = true;
		break;
	case Msr::kIa32GsBase:
		vmcs_field = VmcsField::kGuestGsBase;
		transfer_to_vmcs = true;
		break;
	case Msr::kIa32FsBase:
		vmcs_field = VmcsField::kGuestFsBase;
		transfer_to_vmcs = true;
		break;
	default:
		break;
	}

	LARGE_INTEGER msr_value = {};
	if (is_read) {
		if (transfer_to_vmcs) {
			msr_value.QuadPart = UtilVmRead(vmcs_field);
		}
		else {
			msr_value.QuadPart = UtilReadMsr64(msr);
		}

		p_guest_registers->ax = msr_value.LowPart;
		p_guest_registers->dx = msr_value.HighPart;
	}
	else {
		msr_value.LowPart = (ULONG)p_guest_registers->ax;
		msr_value.HighPart = (ULONG)p_guest_registers->dx;
		if (transfer_to_vmcs) {
			UtilVmWrite(vmcs_field, msr_value.QuadPart);
		}
		else {
			UtilWriteMsr64(msr, msr_value.QuadPart);
		}
	}
}

void PrintExceptionInfo() {
	ULONG_PTR rip = 0;
	rip = UtilVmRead(VmcsField::kGuestRip);

	VmExitInterruptionInformationField exception = { 0 };
	exception.all = UtilVmRead(VmcsField::kVmExitIntrInfo);
	const auto vector = static_cast<InterruptionVector>(exception.fields.vector);

	HYPERPLATFORM_LOG_INFO("rip: %llx, interruption_type: %x, vector: %x", rip, exception.fields.interruption_type, vector);

}

void VmxExceptionOrNmiHandler() 
{
	HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

	//PrintExceptionInfo();

	ULONG_PTR rip = 0;
	rip = UtilVmRead(VmcsField::kGuestRip);

	VmExitInterruptionInformationField exception = { 0 };
	exception.all = UtilVmRead(VmcsField::kVmExitIntrInfo);
	const auto vector = static_cast<InterruptionVector>(exception.fields.vector);

	if (exception.fields.interruption_type
		== static_cast<ULONG32>(InterruptionType::kHardwareException)) {
		exception.fields.valid = true;
		UtilVmWrite(VmcsField::kVmEntryIntrInfoField, exception.all);
	}
	else if (exception.fields.interruption_type
		== static_cast<ULONG32>(InterruptionType::kSoftwareException)) {

		if (vector == InterruptionVector::kBreakpointException) {

			if (PageHookHandleBreakPoint(reinterpret_cast<VOID*>(rip))) {
				return ;
			}
		}
		UtilVmWrite(VmcsField::kVmEntryIntrInfoField, exception.all);
		int exit_inst_length = UtilVmRead(VmcsField::kVmExitInstructionLen);
		UtilVmWrite(VmcsField::kVmEntryInstructionLen, exit_inst_length);
	}
}
BOOLEAN VmxVmcallHandler(GpRegisters* pGuestRegisters)
{
	HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	BOOLEAN ContinueVmx = TRUE;

	if (pGuestRegisters->ax == __EPT_PAGE_HOOK) {
		EptHookVmCall(pGuestRegisters->cx, pGuestRegisters->dx, pGuestRegisters->r8, reinterpret_cast<PULONG64>(pGuestRegisters->r9));
		return ContinueVmx;
	}

	ULONG_PTR num = pGuestRegisters->cx;
	switch (num)
	{
	case CallExitVT:
		ContinueVmx = FALSE;
		VmxPrepareOff(pGuestRegisters);
		break;
	default:
		DbgPrint("VmCall");
		break;
	}

	return ContinueVmx;
}

void VmxCpuidHandler(GpRegisters* p_guest_registers) {

	HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();

	int leaf = static_cast<int>(p_guest_registers->ax);
	int sub_leaf = static_cast<int>(p_guest_registers->cx);
	int result[4] = { 0 };
	__cpuidex((int*)&result, leaf, sub_leaf);

	if (leaf == kHyperVCpuidInterface) {
		result[0] = 'PpyH';
	}

	p_guest_registers->ax = result[0];
	p_guest_registers->bx = result[1];
	p_guest_registers->cx = result[2];
	p_guest_registers->dx = result[3];
}

void VmxInvvpidHandler() {
	HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	FlagRegister guestRFlag;
	guestRFlag.all = UtilVmRead(VmcsField::kGuestRflags);
	guestRFlag.fields.cf = 1;
	UtilVmWrite(VmcsField::kGuestRflags, guestRFlag.all);
}

void VmxInvlpgHandler() {
	HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	const auto invalidate_address =
		reinterpret_cast<void*>(UtilVmRead(VmcsField::kExitQualification));
	UtilInvvpidIndividualAddress(
		static_cast<USHORT>(KeGetCurrentProcessorNumberEx(nullptr) + 1),
		invalidate_address);
}

void VmxRdtscHandler(GpRegisters* pGuestRegisters) {
	HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	ULARGE_INTEGER tsc = { 0 };
	tsc.QuadPart = __rdtsc();
	pGuestRegisters->dx = tsc.HighPart;
	pGuestRegisters->ax = tsc.LowPart;
}

void VmxRdtscpHandler(GpRegisters* pGuestRegisters) {
	HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	DbgPrint("[*] ExitRdtscp\n");
	unsigned int tsc_aux = 0;
	ULARGE_INTEGER tsc = { 0 };
	tsc.QuadPart = __rdtscp(&tsc_aux);
	pGuestRegisters->dx = tsc.HighPart;
	pGuestRegisters->ax = tsc.LowPart;
	pGuestRegisters->cx = tsc_aux;
}

void VmxXsetbvHandler(GpRegisters*  pGuestRegisters) {
	HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	ULARGE_INTEGER value = { 0 };
	value.LowPart = pGuestRegisters->ax;
	value.HighPart = pGuestRegisters->dx;
	_xsetbv(pGuestRegisters->cx, value.QuadPart);
}

void VmxHandleEptViolation() {
	HYPERPLATFORM_PERFORMANCE_MEASURE_THIS_SCOPE();
	const auto cpu_number = KeGetCurrentProcessorNumber();
	auto& vcpu = g_ProcessorData.vcpus[cpu_number];
	EptHandleEptViolation(vcpu.ept_data);
}

EXTERN_C BOOLEAN VmExitHandler(GpRegisters* pGuestRegisters) {

	BOOLEAN vmxContinue = TRUE;

	const VmExitInformation exit_reason = {
	  static_cast<ULONG32>(UtilVmRead(VmcsField::kVmExitReason)) };

	switch (exit_reason.fields.reason) {
	case VmxExitReason::kTripleFault:
	{
		break;
	}
	case VmxExitReason::kEptMisconfig:
	{
		break;
	}
	case VmxExitReason::kEptViolation:
	{
		VmxHandleEptViolation();
		// VmxEptHandler(pGuestRegisters);
		break;
	}
	case VmxExitReason::kCrAccess:
		break;
	case VmxExitReason::kMsrRead:
	{
		VmxMsrReadWriteHandler(pGuestRegisters, true);
		VmxAdjustGuestRip();
		break;
	}
	case VmxExitReason::kMsrWrite:
	{
		VmxMsrReadWriteHandler(pGuestRegisters, false);
		VmxAdjustGuestRip();
		break;
	}
	case VmxExitReason::kCpuid:
	{
		VmxCpuidHandler(pGuestRegisters);
		VmxAdjustGuestRip();
		break;
	}
	case VmxExitReason::kIoInstruction:
	{
		VmxAdjustGuestRip();
		break;
	}
	case VmxExitReason::kVmcall:
	{
		vmxContinue = VmxVmcallHandler(pGuestRegisters);
		if (vmxContinue) VmxAdjustGuestRip();
		break;
	}
	case VmxExitReason::kExceptionOrNmi:
	{
		VmxExceptionOrNmiHandler();
		break;
	}
	case VmxExitReason::kMonitorTrapFlag:
		break;
	case VmxExitReason::kHlt:
		break;
	case VmxExitReason::kVmclear:
	case VmxExitReason::kVmptrld:
	case VmxExitReason::kVmptrst:
	case VmxExitReason::kVmread:
	case VmxExitReason::kVmwrite:
	case VmxExitReason::kVmresume:
	case VmxExitReason::kVmoff:
	case VmxExitReason::kVmon:
	case VmxExitReason::kVmlaunch:
	case VmxExitReason::kVmfunc:
	case VmxExitReason::kInvept:
	case VmxExitReason::kInvvpid:
	{
		VmxInvvpidHandler();
		VmxAdjustGuestRip();
		break;
	}
	case VmxExitReason::kInvd:
	{
		AsmInvd();
		VmxAdjustGuestRip();
		break;
	}
	case VmxExitReason::kInvlpg:
	{
		VmxInvlpgHandler();
		VmxAdjustGuestRip();
		break;
	}
	case VmxExitReason::kRdtsc:
	{
		VmxRdtscHandler(pGuestRegisters);
		VmxAdjustGuestRip();
		break;
	}
	case VmxExitReason::kRdtscp:
	{
		VmxRdtscpHandler(pGuestRegisters);
		VmxAdjustGuestRip();
		break;
	}
	case VmxExitReason::kXsetbv:
	{
		VmxXsetbvHandler(pGuestRegisters);
		VmxAdjustGuestRip();
		break;
	}
	default:
		DbgPrint("[*]Unexpected Exit %d\n", exit_reason.fields.reason);
		// DbgBreakPoint();
		break;

	}

	return vmxContinue;
}