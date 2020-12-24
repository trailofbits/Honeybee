.intel_syntax noprefix

.text
.globl _ha_mirror_take_conditional_thunk, _ha_mirror_take_indirect_branch_thunk, _ha_mirror_call_on_block_outlined

/*
A thunk which routes flow to the correct branch direction
Expectations
    IN
        r11: Virtual IP of the TAKEN BRANCH. You may safely clobber the current virtual IP, pass the taken virtual IP
        r13: The __TEXT address to jump to if we took the branch in the trace
        r14: The __TEXT fallthrough address to jump to if we DID NOT take the branch in the trace.
            This address should set r11 to the appropriate fallthrough value
        rdi: The virtual IP if the branch is not taken. This will replace r11 if the branch is not taken
     OUT:
        rip: If the branch was taken, this thunk routes to the next decoder function (same for not-taken)
            If the trace reports an IP update, however, neither branch will be taken and instead decoding will resume
            at the correct decoding function.
        r11: Updates to the current virtual address after routing
*/
_ha_mirror_take_conditional_thunk:
    sub rsp, 16

    mov rdi, r12 //ha_session ptr
    mov [rsp], rdi //We stash rdi (the NT virtual IP) as a hack. Since take_conditional_c does not write here on override, it'll be there if we need it and not there if we don't. This frees up a register.
    mov rsi, rsp //ptr to override_ip

    mov [rsp + 8], r11 //We stash r11 (the T virtual IP) as a hack. Same as above.
    lea rdx, [rsp + 8] //ptr to override_code_location

    call _ha_session_take_conditional

    mov rdi, [rsp] //unpack our override_ip or NT VIP
    mov r11, [rsp + 8] //unpack our override_code_location or T VIP

    add rsp, 16

    test ax, ax
    js _ha_mirror_block_decode_CLEANUP //A negative return code (instead of 0/1 or NT/T) stops decoding (could be an EOS). Leave in rax.

    //Now we need to decide which of the three address we want to jump to and how we want to update the VIP
    cmp ax, 0x3 //Check if we had an inflight event/we got an override_code_location. 0x3 is the value for inflight
    je _ha_mirror_take_conditional_INFLIGHT_EVENT

    //If we're here, we didn't have an in-flight IP update.
    test ax, ax
    mov rax, r13   //Taken address -- assume we took the branch
    cmovz rax, r14 //and replace it with the not-taken address if we assumed wrong
    cmovz r11, rdi //r11 has the taken VIP (per input rules). Replace it if with NT VIP if we're NT. /* rdi still holds the NT VIP because no override_ip was given by the C function, and so we pulled the old value from the stack */
    jmp rax

    _ha_mirror_take_conditional_INFLIGHT_EVENT:
    //We already unpacked unslid_ip (which the C code updated for us) so we just need our jump addr
    mov rax, r11 //override_code_location
    mov r11, rdi //unpack our override_ip into our virtual IP
    jmp rax //jump to our override_code_location

/*
This is a thunk which quieries the decoder for a new virtual IP, places it in r11, and then jumps to the
correct location to continue decoding.

Expectations:
    IN
        * r11 : the old virtual IP
    OUT
        * r11 : the new virtual IP
*/
_ha_mirror_take_indirect_branch_thunk:
    sub rsp, 16

    mov rdi, r12 //ha_session ptr
    mov [rsp], r11
    mov rsi, rsp // override_ip ptr
    lea rdx, [rsp + 8] //override_code_location ptr
    call _ha_session_take_indirect_branch
    mov r11, [rsp + 0]
    mov rdi, [rsp + 8]

    add rsp, 16

    test ax, ax
    js _ha_mirror_block_decode_CLEANUP //if we have a negative status code we need to terminate (might just be EOS). Leave in rax.
    jmp rdi

_ha_mirror_call_on_block_outlined:
    mov rdi, r12 //ha_session ptr
    mov rsi, r11 //block virtual IP
    mov rax, [r12] //on block function ptr
    call rax
    ret