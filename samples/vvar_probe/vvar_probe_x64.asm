OPTION CASEMAP:NONE

EXTERN g_original_value:QWORD
EXTERN g_replacement_value:QWORD
EXTERN g_stack_observed:QWORD
EXTERN g_constant_observed:DWORD

PUBLIC vvar_register_probe
PUBLIC vvar_register_before_def
PUBLIC vvar_register_live
PUBLIC vvar_register_before_reuse
PUBLIC vvar_register_reused
PUBLIC vvar_stack_probe
PUBLIC vvar_stack_before_def
PUBLIC vvar_stack_live
PUBLIC vvar_constant_probe
PUBLIC vvar_constant_before_def
PUBLIC vvar_constant_live

.code

vvar_register_probe PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog

vvar_register_before_def::
    lea r8d, [rcx+2]
vvar_register_live::
    mov qword ptr [g_original_value], r8
vvar_register_before_reuse::
    mov r8d, 0A5A5A5A5h
vvar_register_reused::
    mov qword ptr [g_replacement_value], r8
    mov rax, qword ptr [g_original_value]
    add rsp, 28h
    ret
vvar_register_probe ENDP

vvar_stack_probe PROC FRAME
    sub rsp, 38h
    .allocstack 38h
    .endprolog

vvar_stack_before_def::
    mov qword ptr [rsp+20h], rcx
vvar_stack_live::
    mov rax, qword ptr [rsp+20h]
    mov qword ptr [g_stack_observed], rax
    add rsp, 38h
    ret
vvar_stack_probe ENDP

vvar_constant_probe PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog

vvar_constant_before_def::
    mov dword ptr [rsp+20h], 2
vvar_constant_live::
    mov eax, dword ptr [rsp+20h]
    mov dword ptr [g_constant_observed], eax
    add rsp, 28h
    ret
vvar_constant_probe ENDP

END
