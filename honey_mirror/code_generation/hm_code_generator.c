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
    FILE *fp = fopen(code_destination_path, "w");
    if (!fp) {
        result = -1;
    }

    //Write out the asm header
    fprintf(fp,
            ".intel_syntax noprefix\n"
            ".text\n"
            ".globl _block_decode, _block_decode_CLEANUP, _unslid_virtual_ip_to_text, "
            "_unslid_virtual_ip_to_text_count\n"
            "_block_decode:\n"
            "\t#Epilogue\n"
            "\tsub  rsp, 32\n"
            "\tmov [rsp + 0], r12 #IP\n"
            "\t/* These registers are used for the _take_conditional thunk */\n"
            "\tmov [rsp + 8], r13 #Taken jump address\n"
            "\tmov [rsp + 16], r14 #Not-taken fallthrough jump address\n"
            "\tmov [rsp + 24], rbx #Taken virtual IP\n"

            "\tmov r12, rdi #Stash IP\n"
            "\t//Jump to the starting point (pass rsi through)\n"
            "\tcall table_search_ip\n"
            "\tjmp rax\n\n"
    );

    for (int64_t i = 0; i < block_count; i++) {
        const hm_disassembly_block *block = sorted_blocks + i;

        //Write out the block header (which logs coverage
        fprintf(fp,
                "\t_%p:\n" //This block's label
                "\t\tcall _log_coverage\n",
                (void *)block->start_offset);

        int64_t next_block_i = -1;
        if (block->cofi_destination == UINT64_MAX
        || (next_block_i = lookup_block_sorted(sorted_blocks, block_count, block->cofi_destination)) == -1) {
            //We don't have a known next-IP, use the any-jump
            fprintf(fp, "\t\tjmp _take_indirect_branch\n");
        } else if (block->instruction_category == XED_CATEGORY_COND_BR) {
            void *not_taken = (void *)(block->start_offset + block->length + block->last_instruction_size);
            void *taken = (void *)sorted_blocks[next_block_i].start_offset;
            fprintf(fp,
                    "\t\tlea r13, _%p\n"
                    "\t\tlea r14, _%p_fallthrough\n"
                    "\t\tmov rbx, %p\n"
                    "\t\tjmp _take_conditional\n"
                    "\t_%p_fallthrough:\n"
                    "\t\tmov r12, %p\n",
                    taken, (void *) block->start_offset, (void *) block->cofi_destination,
                    (void *) block->start_offset, not_taken);
        } else {
            //We have an unconditional branch. This means we KNOW our target
            void *taken = (void *)sorted_blocks[next_block_i].start_offset;
            fprintf(fp,
                    "\t\tmov r12, %p\n"
                    "\t\tjmp _%p\n",
                    (void *) block->cofi_destination, taken);
        }
    }

    //Write the epilogue
    fprintf(fp,
            "\t\t_block_decode_CLEANUP:"
            "\t#Prologue\n"
            "\tmov r12, [rsp + 0]\n"
            "\tmov r13, [rsp + 8]\n"
            "\tmov r14, [rsp + 16]\n"
            "\tmov rbx, [rsp + 24]\n"
            "\tadd rsp, 32\n"
            "\tret\n\n");

    /* write the floor unslide-ip to label data table */

    fprintf(fp, ".rodata\n"
                "_unslid_virtual_ip_to_text_count:\n"
                ".quad %p\n"
                "_unslid_virtual_ip_to_text:\n",
            (void *) block_count);
    for (int64_t i = 0; i < block_count; i++) {
        const hm_disassembly_block *block = sorted_blocks + i;
        fprintf(fp,
                ".quad %p\n"
                ".quad _%p\n",
                (void *) block->start_offset,
                (void *) block->start_offset);
    }

    //Add a final entry with max values
    //We do this so that we can safely lookup the ""size"" of any entry without doing a bounds check
    //The last entry will just be ridiculously large, but this doesn't matter since we use this to floor
    fprintf(fp,
            ".quad %p\n"
            ".quad %p\n",
            (void *) UINT64_MAX,
            (void *) UINT64_MAX);

    fclose(fp);

    return 0;
}
