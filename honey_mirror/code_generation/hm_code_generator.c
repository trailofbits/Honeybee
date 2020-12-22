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
            ".globl _block_decode\n"
            "_log_coverage:\n"
            "\t//We're cheating here and violating CC, the IP is in callee saved r12\n"
            "\tret\n"
            "\n"
            "_should_take_conditional:\n"
            "\t//We're cheating here and violating CC and intentionally dumping a test result down\n"
            "\ttest rax, rax\n"
            "\tret\n"
            "\n"
            "_get_indirect_branch:\n"
            "\t//We're cheating here and violating CC, the IP is in callee saved r12\n"
            "\txor rax, rax #return the PC to jump to\n"
            "\txor r12, r12 #update the IP\n"
            "\tret\n"
            "_block_decode:\n"
            "\t#Epilogue\n"
            "\tsub  rsp, 16\n"
            "\tmov [rsp + 0], r12 #IP\n");

    for (int64_t i = 0; i < block_count; i++) {
        const hm_disassembly_block *block = sorted_blocks + i;

//        snprintf(block_label_buffer, sizeof(block_label_buffer), "\t_%p:\n", (void *)block->start_offset);
        //Write out the block header (which logs coverage
        fprintf(fp,
                "\t_%p:\n" //This block's label
                "\t\tcall _log_coverage\n",
                (void *)block->start_offset);

        int64_t next_block_i = -1;
        if (block->cofi_destination == UINT64_MAX
        || (next_block_i = lookup_block_sorted(sorted_blocks, block_count, block->cofi_destination)) == -1) {
            //We don't have a known next-IP, use the any-jump
            fprintf(fp,
                    "\t\tcall _get_indirect_branch\n"
                    /* we don't need to update r12 because we violated CC */
                    "\t\tjmp rax\n"
                    );
        } else if (block->instruction_category == XED_CATEGORY_COND_BR) {
            void *not_taken = (void *)(block->start_offset + block->length + block->last_instruction_size);
            void *taken = (void *)sorted_blocks[next_block_i].start_offset;
            fprintf(fp,
                    "\t\tcall _should_take_conditional\n"
                    "\t\tmov r12, %p\n"
                    "\t\tjz _%p\n" //not taken
                    "\t\tmov r12, %p\n"
                    "\t\tjmp _%p\n", //taken
                    not_taken, not_taken,
                    (void *)block->cofi_destination, taken);
        } else {
            //We have an unconditional branch. This means we KNOW our target
            void *taken = (void *)sorted_blocks[next_block_i].start_offset;
            fprintf(fp,
                    "\t\tmov r12, %p\n"
                    "\t\tjmp _%p\n",
                    (void *)block->cofi_destination, taken);
        }
    }
    
    //Write the epilogue
    fprintf(fp,
            "\t#Prologue\n"
            "\tmov r12, [rsp + 0]\n"
            "\tadd rsp, 16\n"
            "\tret\n");

    return 0;
}
