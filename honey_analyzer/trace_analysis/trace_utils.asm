.intel_syntax noprefix
.data
LOG_COVERAGE_PRINTF: .asciz "ip = %p\n"
BLOCK_ABORT_PRINTF: .asciz "Bad status code: %d\n"

.text
.globl /*_log_coverage,*/ _take_conditional, _take_indirect_branch

/*
_log_coverage:
	//We're cheating here and violating CC, the IP is in callee saved r12
	lea rdi, LOG_COVERAGE_PRINTF
	mov rsi, r12
    xor rax, rax
	call printf
	ret
*/

/*
A thunk which routes flow to the correct branch direction
Expectations
    IN
        r12: Virtual IP
        r13: The __TEXT address to jump to if we took the branch in the trace
        r14: The __TEXT fallthrough address to jump to if we DID NOT take the branch in the trace.
            This address should set r12 to the appropriate fallthrough value
        rbx: The virtual IP if the branch is taken
     OUT:
        rip: If the branch was taken, this thunk routes to the next decoder function (same for not-taken)
            If the trace reports an IP update, however, neither branch will be taken and instead decoding will resume
            at the correct decoding function.
        r12: Updates to the current virtual address after routing
*/
_take_conditional:
    sub rsp, 16

    mov [rsp], r12
    mov rdi, rsp //ptr to unslid_ip

    mov QWORD PTR[rsp + 8], 0
    lea rsi, [rsp + 8] //ptr to override next_code_location
    call _take_conditional_c

    mov r12, [rsp] //unpack our new unslid_ip
    mov r11, [rsp + 8] //unpack our next_code_location

    add rsp, 16

    test ax, ax
    js _block_decode_abort //A negative return code (instead of 0/1 or NT/T) is an abort

    //Now we need to decide which of the three address we want to jump to and how we want to update the virtual IP
    test r11, r11 //Check if our IP changes as a result of an in-flight event
    jnz _take_conditional_INFLIGHT_EVENT

    //If we're here, we didn't have an in-flight IP update.
    test ax, ax
    mov rax, r13 #Taken address -- assume we took the branch
    cmovz rax, r14 #Not-taken address -- and replace it we we assumed wrong
    mov r12, rbx //Move the taken virtual IP into our IP slot. If we end up jumping to fallthrough it'll be reset anyways
    jmp rax

    _take_conditional_INFLIGHT_EVENT:
    //We already unpacked unslid_ip (which the C code updated for us) so we just need our jump addr
    mov rax, r11
    jmp rax


/*
This is a fake ""TCO"" routine which quieries the decoder for a new virtual IP, places it in r12, and then jumps to the
correct location to continue decoding. This is a thunk, jump to this.

Expectations:
    IN
        * r12 : the old virtual IP
    OUT
        * r12 : the new virtual IP
*/
_take_indirect_branch:
    sub rsp, 16

    mov [rsp], r12
    mov rdi, rsp
    lea rsi, [rsp + 8]
    call _take_indirect_branch_c
    mov r12, [rsp + 0]
    mov rdi, [rsp + 8]

    add rsp, 16

    test ax, ax
    js _block_decode_abort //if we have a negative status code, something is broken
    jmp rdi


/*
Thunk which displays an error code from RAX and then tears down block_decode
*/
_block_decode_abort:
    lea rdi, [rip + BLOCK_ABORT_PRINTF]
    mov rsi, rax //status code
    xor rax, rax
    call _printf

    jmp _block_decode_CLEANUP