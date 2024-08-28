PUBLIC AsmVmxLaunch
PUBLIC AsmVmmEntryPoint
EXTERN VmExitHandler:PROC

PUSHAQ MACRO
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1     
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
ENDM

POPAQ MACRO
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8  
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
ENDM

.CONST 
VMX_OK                      EQU     0
VMX_ERROR_WITH_STATUS       EQU     1
VMX_ERROR_WITHOUT_STATUS    EQU     2

.CODE
AsmVmxLaunch PROC
    pushfq 
    PUSHAQ
    ; BOOLEAN SetupVMCS(PVOID guestStack, PVOID guestResumeRip)
    mov rax,rcx
    mov rcx, rsp
    mov rdx, VmLaunchToGuest ; call SetupVMCS
    sub rsp,100h ; ����ȥ�Ĳ�����Ҫ������ջ�У���˿����㹻��λ�÷Ų���
                 ;   mov     [rsp+guestResumeRip], rdx
                 ;   mov     [rsp+guestStack], rcx
    call rax
    add rsp,100h

    ; ��ִ�гɹ�������ִ�е�����
    POPAQ
    popfq
    xor rax,rax
    ret

VmLaunchToGuest:
    POPAQ
    popfq
    xor rax,rax
    inc rax
    ret

AsmVmxLaunch ENDP

;���ص�VmExit�¼�������ʱ�򣬴����￪ʼ�������ǵĴ�����VmexitHandler
AsmVmmEntryPoint PROC
	PUSHAQ			;��guestת��vmmʱ,ͨ�üĴ���������ı�.�������Ĵ��������vmcs guest����,����rflags

	mov rcx,rsp
	sub rsp,50h
	call VmexitHandler;�ú���ִ�������ֽ��,һ����������Ԥ�ڵ�vmexitֱ�Ӷϵ�.����0��������,��Ҫvmresume. ����1�˳�vmx,�ص�guest
	add rsp,50h
	test al,al
	jz ExitVmx		;����0���˳�vmx

	POPAQ
	vmresume		;�����vmcs��guest����лָ�guest״̬,ֻ��ͨ�üĴ�����Ҫ�ֶ��ָ�
	jmp ErrorHandler	;�����Guestʧ�ܲŻ�ִ������
ExitVmx:
	POPAQ
	vmxoff			;ִ�����rax=rflags,rdx=ԭ����ջ,rcx=����vmexit����һ��ָ���ַ
	jz ErrorHandler             ; if (ZF) jmp
    jc ErrorHandler             ; if (CF) jmp
    push rax
    popfq                  ; rflags <= GuestFlags
    mov rsp, rdx            ; rsp <= GuestRsp
    push rcx
    ret                     ; jmp AddressToReturn
ErrorHandler:
    int 3
AsmVmmEntryPoint ENDP



AsmVmCall proc
	mov rax,rcx; //��־
	mov rcx,rdx;
	mov rdx,r8;
	mov r8,r9;
	mov r9,[rsp + 028h];
	;lea rcx,[__RETVALUE];  //���ص�ַ
	;mov rdx,rsp;   //Ҫ���ص�EIP
	vmcall
;__RETVALUE:
	ret;
AsmVmCall endp;


AsmVmxCall PROC
    vmcall                  ; vmcall(hypercall_number, context)
    ret
AsmVmxCall ENDP


Asminvept proc
	invept rcx, OWORD PTR [rdx]
	ret;
Asminvept endp

AsmInvd PROC
    invd
    ret
AsmInvd ENDP

AsmInvvpid PROC
    invvpid rcx, oword ptr [rdx]
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmInvvpid ENDP


; void AsmWriteGDT(_In_ const GDTR *gdtr);
AsmWriteGDT PROC
    lgdt fword ptr [rcx]
    ret
AsmWriteGDT ENDP

; void AsmWriteLDTR(_In_ USHORT local_segmeng_selector);
AsmWriteLDTR PROC
    lldt cx
    ret
AsmWriteLDTR ENDP

; USHORT AsmReadLDTR();
AsmReadLDTR PROC
    sldt ax
    ret
AsmReadLDTR ENDP

; void AsmWriteTR(_In_ USHORT task_register);
AsmWriteTR PROC
    ltr cx
    ret
AsmWriteTR ENDP

; USHORT AsmReadTR();
AsmReadTR PROC
    str ax
    ret
AsmReadTR ENDP

; void AsmWriteES(_In_ USHORT segment_selector);
AsmWriteES PROC
    mov es, cx
    ret
AsmWriteES ENDP

; USHORT AsmReadES();
AsmReadES PROC
    mov ax, es
    ret
AsmReadES ENDP

; void AsmWriteCS(_In_ USHORT segment_selector);
AsmWriteCS PROC
    mov cs, cx
    ret
AsmWriteCS ENDP

; USHORT AsmReadCS();
AsmReadCS PROC
    mov ax, cs
    ret
AsmReadCS ENDP

; void AsmWriteSS(_In_ USHORT segment_selector);
AsmWriteSS PROC
    mov ss, cx
    ret
AsmWriteSS ENDP

; USHORT AsmReadSS();
AsmReadSS PROC
    mov ax, ss
    ret
AsmReadSS ENDP

; void AsmWriteDS(_In_ USHORT segment_selector);
AsmWriteDS PROC
    mov ds, cx
    ret
AsmWriteDS ENDP

; USHORT AsmReadDS();
AsmReadDS PROC
    mov ax, ds
    ret
AsmReadDS ENDP

; void AsmWriteFS(_In_ USHORT segment_selector);
AsmWriteFS PROC
    mov fs, cx
    ret
AsmWriteFS ENDP

; USHORT AsmReadFS();
AsmReadFS PROC
    mov ax, fs
    ret
AsmReadFS ENDP

; void AsmWriteGS(_In_ USHORT segment_selector);
AsmWriteGS PROC
    mov gs, cx
    ret
AsmWriteGS ENDP

; USHORT AsmReadGS();
AsmReadGS PROC
    mov ax, gs
    ret
AsmReadGS ENDP

; ULONG_PTR AsmLoadAccessRightsByte(_In_ ULONG_PTR segment_selector);
AsmLoadAccessRightsByte PROC
    lar rax, rcx
    ret
AsmLoadAccessRightsByte ENDP

END