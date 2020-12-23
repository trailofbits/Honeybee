.intel_syntax noprefix
.rodata
LOG_COVERAGE_PRINTF: .asciz "ip = %p\n"
BLOCK_ABORT_PRINTF: .asciz "Bad status code: %d\n"

.text
.globl /*_log_coverage,*/ _should_take_conditional, _take_indirect_branch

/*
_log_coverage:
	//We're cheating here and violating CC, the IP is in callee saved r12
	lea rdi, LOG_COVERAGE_PRINTF
	mov rsi, r12
    xor rax, rax
	call printf
	ret
*/

_should_take_conditional:
    sub rsp, 16

    mov rdi, rsp
    mov [rsp], r12 //ptr to unslid_ip
    mov rsi, rsp
    add rsi, 8
    xor rax, rax
    mov [rsi], rax //ptr to override next_code_location
    call should_take_conditional_c

    mov r12, [rsp] //unpack our new unslid_ip
    mov r11, [rsp + 8] //unpack our next_code_location

    add rsp, 16

    test ax, ax
    js _block_decode_abort_2 //check for a negative error


    test r11, r11
    jnz _should_take_conditional_ROP //Check if our IP changed as a result of an in-flight event

    //We're good to go. Leak the test result out of the procedure so the branch is set correctly
    test ax, ax
    ret

    //FIXME: Restructure this so we aren't literally using a rop here
    _should_take_conditional_ROP:
    //Since the IP changed as we were decoding, we ignore this T/NT result and resume at the IP of the last event
    //I structured this poorly and so since this is a function call we need to cheat and redirect execution to the
    //correct/new function call rather than resuming the old one

    /* SOLUTION!!! Re-build the code generator so that it passes the two choices on caller saved registers. This means
    we don't return at all and this is just another thunk */
    mov [rsp], r11
    ret

    _block_decode_abort_2:
    //FIXME: Apply above solution, same hack
    lea r11, _block_decode_abort
    mov [rsp], r11
    ret


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
    mov rsi, rsp
    add rsi, 8
    call take_indirect_branch_c
    mov r12, [rsp + 0]
    mov rdi, [rsp + 8]

    add rsp, 16

    test ax, ax
    js _block_decode_abort //if we have a negative status code, something is broken
    jmp rdi


_block_decode_abort:
    lea rdi, BLOCK_ABORT_PRINTF
    mov rsi, rax //status code
    xor rax, rax
    call printf

    /* since we are still technically TCO, we need to use the block decode cleanup otherwise the stack is broken */
    jmp _block_decode_CLEANUP