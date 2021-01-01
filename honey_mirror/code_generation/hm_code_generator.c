//
// Created by Allison Husain on 12/21/20.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xed-interface.h"

#include "hm_code_generator.h"

static int64_t lookup_block_sorted(const hm_disassembly_block *sorted_blocks, int64_t block_count, uint64_t
target_offset) {
    int64_t left = 0, right = block_count - 1;
    while (left <= right && right >= 0) {
        int64_t search = (left + right) / 2;
        const hm_disassembly_block *block = &sorted_blocks[search];
        uint64_t block_start = block->start_offset;
        uint64_t block_end = block_start + block->length;

        if (block_start <= target_offset && target_offset <= block_end) {
            return search;
        } else if (target_offset < block_start) {
            right = search - 1;
        } else {
            left = search + 1;
        }
    }

    return -1;
}

int hm_code_generator_generate(const hm_disassembly_block *sorted_blocks, int64_t block_count, const char
*code_destination_path) {
    int result = 0;
    FILE *fp = NULL;
    size_t cofi_destination_size_bytes = 0;
    int64_t *cofi_destination_block_indexes = NULL;

    fp = fopen(code_destination_path, "w");
    if (!fp) {
        result = -1;
        goto CLEANUP;
    }

    if (__builtin_mul_overflow(block_count, sizeof(int64_t), &cofi_destination_size_bytes)
        || !(cofi_destination_block_indexes = malloc(cofi_destination_size_bytes))) {
        result = -2;
        goto CLEANUP;
    }

    uint64_t direct_map_count;
    {
        const hm_disassembly_block *last_block = &sorted_blocks[block_count - 1];
        direct_map_count = last_block->start_offset + last_block->length + last_block->last_instruction_size
                - sorted_blocks[0].start_offset;
    };


    //Write out the asm header
    fprintf(fp,
            ".intel_syntax noprefix\n"
            ".text\n"
            ".globl _ha_mirror_block_decode, _ha_mirror_block_decode_CLEANUP, _ha_mirror_block_decode_JUMP_VIRTUAL, "
            "_ha_mirror_direct_map, _ha_mirror_direct_map_count, _ha_mirror_direct_map_address_slide\n"
            "_ha_mirror_block_decode:\n"
            "\t#Epilogue\n"
            "\tsub  rsp, 56\n"
            "\tmov [rsp + 0], r12 #ha_session ptr\n"
            "\t/* These registers are used for the _take_conditional_thunk thunk since they are callee saved */\n"
            "\tmov [rsp + 8], r13 #Taken jump address\n"
            "\tmov [rsp + 16], r14 #Not-taken fallthrough jump address\n"
            "\tmov [rsp + 24], r15 #_ha_mirror_block_decode_ANY_JUMP, 3 bytes instead of 5.\n"
            "\tmov [rsp + 32], rbp #_ha_mirror_log_coverage, jmp rbp is just 2 bytes instead of 5.\n"
            "\tmov [rsp + 40], rbx #_ha_mirror_take_conditional_thunk, jmp rbx is just 2 instead of 5.\n"
            "\tmov r11, 0 #init our virtual IP register\n"
            "\tmov r12, rdi #Stash our ha_session ptr\n"
            "\tlea r15, [rip + _ha_mirror_block_decode_ANY_JUMP]\n"
            "\tlea rbp, [rip + _ha_mirror_call_on_block_outlined]\n"
            "\tlea rbx, [rip + _ha_mirror_take_conditional_thunk]\n"
            "\t//We don't know where to start, ask the decoder\n"
            "\tjmp _ha_mirror_take_indirect_branch_thunk\n\n"

            //This thunk reroutes us using a slid r11 VIP
            //Invalid IPs that are in-range redirect to the invalid address handler
            //Invalid IPs that are out of range redirect to the invalid address handler
            "\t_ha_mirror_block_decode_JUMP_VIRTUAL:\n"
            "\t\t//The register we want to jump to is in r11, use the direct map to get to the segment\n"
            "\t\tmov rsi, r11\n"
            "\t\tsub rsi, %llu //Shift our VIP to the index of our table\n"
            "\t\tcmp rsi, %llu //Check if our index is in bounds. We use an unsigned compare to catch negatives.\n"
            "\t\tjae _ha_mirror_block_decode_INVALID_ADDRESS\n"
            "\t\tlea rdi, [_ha_mirror_direct_map + rip]\n"
            "\t\tlea rax, [_ha_mirror_id_to_offset_map + rip]\n"
            "\t\tmovsxd rsi, dword ptr [rdi + 4 * rsi]\n"
            "\t\tmovsxd rsi, dword ptr [rax + 4 * rsi]\n"
            "\t\tlea rcx, [rip + _ha_mirror_block_decode_JUMP_VIRTUAL]\n"
            "\t\tadd rsi, rcx\n"
            "\t\tjmp rsi\n\n"

            //This handler is hit when the direct map lands on an invalid address
            "\t_ha_mirror_block_decode_INVALID_ADDRESS:\n"
            "\t\tmov rax, -6 //HA_PT_DECODER_TRACE_DESYNC\n"
            "\t\tjmp _ha_mirror_block_decode_CLEANUP\n\n"

            //We use a shared "any jump" procedure for all indirect branches since they're the same except with a different
            // r11. For performance and code size reasons, we merge them all.
            "\t_ha_mirror_block_decode_ANY_JUMP:\n"
            "\t\tcall rbp #_log_coverage\n"
            "\t\tjmp _ha_mirror_take_indirect_branch_thunk\n",
            sorted_blocks[0].start_offset, direct_map_count
    );

    //Generate our cofi destination table
    for (int64_t i = 0; i < block_count; i++) {
        const hm_disassembly_block *block = sorted_blocks + i;

        int64_t next_block_i = -1;
        if (block->cofi_destination == UINT64_MAX
            || (next_block_i = lookup_block_sorted(sorted_blocks, block_count, block->cofi_destination)) == -1) {
            //We don't have a known next-IP
            cofi_destination_block_indexes[i] = -1;
        } else {
            cofi_destination_block_indexes[i] = next_block_i;
        }
    }

    //Write out all other blocks
    for (int64_t i = 0; i < block_count; i++) {
        const hm_disassembly_block *block = sorted_blocks + i;
        int64_t next_block_i = cofi_destination_block_indexes[i];

        if (next_block_i < 0) {
            //This block was already handled by the any jump, don't write it out
            continue;
        }

        //Write out the block header (which logs coverage
        fprintf(fp,
                "\t_%p:\n" //This block's label
                "\t\tcall rbp #_ha_mirror_call_on_block_outlined\n",
                (void *)block->start_offset);

        if (block->instruction_category == XED_CATEGORY_COND_BR) {
            void *not_taken = (void *)(block->start_offset + block->length + block->last_instruction_size);
            void *taken = (void *)sorted_blocks[next_block_i].start_offset;

            if (cofi_destination_block_indexes[next_block_i] < 0) {
                fprintf(fp, "\t\tmov r13, r15 #_ha_mirror_block_decode_ANY_JUMP\n");
            } else {
                fprintf(fp, "\t\tlea r13, [rip + _%p]\n", taken);
            }

            if (i + 1 < block_count && cofi_destination_block_indexes[i + 1] < 0) {
                fprintf(fp, "\t\tmov r14, r15 #_ha_mirror_block_decode_ANY_JUMP\n");
            } else {
                fprintf(fp, "\t\tlea r14, [rip + _%p]\n", not_taken);
            }

            fprintf(fp,
                    "\t\tmov r11, %p\n"
                    "\t\tmov rdi, %p\n"
                    "\t\tjmp rbx #_ha_mirror_take_conditional_thunk\n",
                    (void *) block->cofi_destination,
                    not_taken);
        } else {
            //We have an unconditional branch. This means we KNOW our target
            void *taken = (void *)sorted_blocks[next_block_i].start_offset;
            fprintf(fp, "\t\tmov r11, %p\n", (void *) block->cofi_destination);
            if (cofi_destination_block_indexes[next_block_i] < 0) {
                fprintf(fp, "\t\tjmp r15 #_ha_mirror_block_decode_ANY_JUMP\n");
            } else {
                fprintf(fp, "\t\tjmp _%p\n", taken);
            }
        }
    }

    //Write the epilogue
    fprintf(fp,
            "\t_ha_mirror_block_decode_CLEANUP:\n"
            "\t#Prologue -- be sure to put a return value in rax!\n"
            "\tmov r12, [rsp + 0]\n"
            "\tmov r13, [rsp + 8]\n"
            "\tmov r14, [rsp + 16]\n"
            "\tmov r15, [rsp + 24]\n"
            "\tmov rbp, [rsp + 32]\n"
            "\tmov rbx, [rsp + 40]\n"
            "\tadd rsp, 56\n"
            "\tret\n\n");

    /*
     * The mapping structure is a two table pair
     * This is done because the linker gives up on us if we have too many relocations and so we have to be somewhat
     * conservative about how we use them
     */

    fprintf(fp, ".data\n"
                "_ha_mirror_id_to_offset_map:\n"
                ".long _ha_mirror_block_decode_INVALID_ADDRESS - _ha_mirror_block_decode_JUMP_VIRTUAL //0\n"
                ".long _ha_mirror_block_decode_ANY_JUMP - _ha_mirror_block_decode_JUMP_VIRTUAL //1\n"
                );
    bool last_was_indirect = false;
    for (int64_t i = 0; i < block_count; i++) {
        const hm_disassembly_block *block = sorted_blocks + i;
        bool is_indirect = cofi_destination_block_indexes[i] < 0;
        if (!is_indirect) {
            fprintf(fp, ".long _%p - _ha_mirror_block_decode_JUMP_VIRTUAL\n", (void *) block->start_offset);
        }
    }

    /* write the floor unslide-ip to label data table */
    fprintf(fp, "_ha_mirror_direct_map:\n");
    uint32_t offset_map_index = 2;
    uint64_t last_block_ip = sorted_blocks[0].start_offset;
    for (int64_t i = 0; i < block_count; i++) {
        const hm_disassembly_block *block = sorted_blocks + i;
        bool is_indirect = cofi_destination_block_indexes[i] < 0;

        uint64_t invalid_count = block->start_offset - last_block_ip;
        uint64_t this_block_count = block->length + block->last_instruction_size;
        //invalid
        fprintf(fp, ".fill %llu, 4, 0\n", invalid_count);
        last_block_ip = block->start_offset + this_block_count;

        if (is_indirect) {
            //any jump
            fprintf(fp, ".fill %llu, 4, 1\n", this_block_count);
        } else {
            fprintf(fp, ".fill %llu, 4, %u\n", this_block_count, offset_map_index);
            offset_map_index++;
        }
    }

    fprintf(fp,
            "_ha_mirror_direct_map_count:\n"
            ".quad %llu\n"
            "_ha_mirror_direct_map_address_slide:\n"
            ".quad %llu\n"
            , direct_map_count, sorted_blocks[0].start_offset);

    CLEANUP:
    if (fp) {
        fclose(fp);
    }

    if (cofi_destination_block_indexes) {
        free(cofi_destination_block_indexes);
    }

    return result;
}
