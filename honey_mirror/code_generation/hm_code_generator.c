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

    //Write out the asm header
    fprintf(fp,
            ".intel_syntax noprefix\n"
            ".text\n"
            ".globl _ha_mirror_block_decode, _ha_mirror_block_decode_CLEANUP, _ha_mirror_unslid_virtual_ip_to_text, "
            "_ha_mirror_unslid_virtual_ip_to_text_count\n"
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


    //We use a shared "any jump" procedure for all indirect branches since they're the same except with a different
    // r11. For performance and code size reasons, we merge them all.
    fprintf(fp,
            "\t_ha_mirror_block_decode_ANY_JUMP:\n"
            "\t\tcall rbp #_log_coverage\n"
            "\t\tjmp _ha_mirror_take_indirect_branch_thunk\n"
            );

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

    /* write the floor unslide-ip to label data table */
    fprintf(fp, ".data\n"
                "_ha_mirror_unslid_virtual_ip_to_text:\n");

    //We can shrink the number of items in our table by joining contiguous indirect blocks (since they all go to the
    // same location).
    bool last_was_indirect = false;
    int64_t table_true_count = 0;
    for (int64_t i = 0; i < block_count; i++) {
        const hm_disassembly_block *block = sorted_blocks + i;
        bool is_indirect = cofi_destination_block_indexes[i] < 0;
        if (!last_was_indirect /* if the last wasn't indirect, we have to emit as we have nobody to join to */
            || !is_indirect /* if we aren't indirect we have to emit */
            ) {
            fprintf(fp, ".quad %p\n", (void *) block->start_offset);

            if (is_indirect) {
                fprintf(fp, ".quad _ha_mirror_block_decode_ANY_JUMP\n");
            } else {
                fprintf(fp, ".quad _%p\n", (void *) block->start_offset);
            }

            last_was_indirect = is_indirect;
            table_true_count++;
        }
    }

    //Add a final entry with max values
    //We do this so that we can safely lookup the ""size"" of any entry without doing a bounds check
    //The last entry will just be ridiculously large, but this doesn't matter since we use this to floor
    fprintf(fp,
            ".quad %p\n"
            ".quad %p\n"
            "_ha_mirror_unslid_virtual_ip_to_text_count:\n"
            ".quad %p\n"
            "_ha_mirror_real_basic_block_count:\n"
            ".quad %p\n",
            (void *) UINT64_MAX,
            (void *) UINT64_MAX,
            (void *)table_true_count,
            (void *)block_count);

    CLEANUP:
    if (fp) {
        fclose(fp);
    }

    if (cofi_destination_block_indexes) {
        free(cofi_destination_block_indexes);
    }

    return result;
}
