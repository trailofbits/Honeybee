//
// Created by Allison Husain on 12/21/20.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xed-interface.h"

#include "hh_hive_generator.h"
#include "../../honeybee_shared/hb_hive.h"

static int64_t lookup_block_sorted(const hh_disassembly_block *sorted_blocks, int64_t block_count, uint64_t
target_offset) {
    int64_t left = 0, right = block_count - 1;
    while (left <= right && right >= 0) {
        int64_t search = (left + right) / 2;
        const hh_disassembly_block *block = &sorted_blocks[search];
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

#define LO31(x) ((uint64_t)((x) & ((1LLU<<31) - 1)))
/**
 * Calculate the packed index value according to the format described in hb_hive.h
 */
static inline uint64_t packed_indices(uint64_t not_taken, uint64_t taken, uint8_t is_conditional) {
    return (LO31(not_taken) << 33) | LO31(taken) << 1 | (is_conditional & 0b1);
}

/**
 * Calculate the packed virtual address pointers according to the format described in hb_hive.h
 */
static inline uint64_t packed_uvip(uint64_t not_taken, uint64_t taken) {
    return (not_taken << 32) | LO31(taken);
}

/**
 * Write a uint32_t a certain number of times to a file.
 */
static inline void write_uint32t_times(FILE *fp, uint32_t value, uint64_t times) {
    for (uint64_t i = 0; i < times; i++) {
        fwrite(&value, sizeof(value), 1, fp);
    }
}

int hh_hive_generator_generate(const hh_disassembly_block *sorted_blocks, int64_t block_count, const char
*hive_destination_path) {
    int result = 0;
    FILE *fp = NULL;
    size_t cofi_destination_size_bytes = 0;
    int64_t *cofi_destination_block_indexes = NULL;

    fp = fopen(hive_destination_path, "w");
    if (!fp) {
        result = -1;
        goto CLEANUP;
    }

    //Write out our header
    hb_hive_file_header header = {
            .magic = HB_HIVE_FILE_HEADER_MAGIC,
            .block_count = block_count,
            .uvip_slide = sorted_blocks[0].start_offset,
            .direct_map_count = sorted_blocks[block_count - 1].start_offset + sorted_blocks[block_count - 1].length - sorted_blocks[0].start_offset,
    };
    fwrite(&header, sizeof(hb_hive_file_header), 1, fp);

    /* Generate our cofi destination table */

    if (__builtin_mul_overflow(block_count, sizeof(int64_t), &cofi_destination_size_bytes)
        || !(cofi_destination_block_indexes = malloc(cofi_destination_size_bytes))) {
        result = -2;
        goto CLEANUP;
    }

    for (int64_t i = 0; i < block_count; i++) {
        const hh_disassembly_block *block = sorted_blocks + i;

        int64_t next_block_i = -1;
        if (block->cofi_destination == UINT64_MAX
            || (next_block_i = lookup_block_sorted(sorted_blocks, block_count, block->cofi_destination)) == -1) {
            //We don't have a known next-IP
            cofi_destination_block_indexes[i] = -1;
        } else {
            cofi_destination_block_indexes[i] = next_block_i;
        }
    }

    hm_block out_block;
    bzero(&out_block, sizeof(hm_block));

    //Write out all blocks
    for (int64_t i = 0; i < block_count; i++) {
        const hh_disassembly_block *block = sorted_blocks + i;
        int64_t next_block_i = cofi_destination_block_indexes[i];
        uint64_t next_block_start_offset;
        if (next_block_i != -1) {
            next_block_start_offset = sorted_blocks[next_block_i].start_offset;
        } else {
            next_block_start_offset = header.uvip_slide - 1;
        }

        if (block->instruction_category == XED_CATEGORY_COND_BR) {
            out_block.packed_indices = packed_indices(/* NT */ i + 1, /* T */ next_block_i, /* COND? */ 1);
            out_block.packed_uvips = packed_uvip(/* NT */ block->start_offset + block->length + block->last_instruction_size - header.uvip_slide, /* T */ next_block_start_offset  - header.uvip_slide);
        } else {
            //We have an unconditional branch. This means we KNOW our target
            out_block.packed_indices = packed_indices(/* NT */ 0, /* T */ next_block_i, /* COND? */ 0);
            out_block.packed_uvips = packed_uvip(/* NT */ 0, /* T */ next_block_start_offset  - header.uvip_slide);
        }
        fwrite(&out_block, sizeof(hm_block), 1, fp);
    }

    //Write out our direct map
    uint64_t last_block_ip = sorted_blocks[0].start_offset;
    for (int64_t i = 0; i < block_count; i++) {
        const hh_disassembly_block *block = sorted_blocks + i;

        uint64_t invalid_count = block->start_offset - last_block_ip;
        uint64_t this_block_count = block->length + block->last_instruction_size;
        //invalid
        write_uint32t_times(fp, 0, invalid_count);
        //valid
        write_uint32t_times(fp, (uint32_t)i, this_block_count);

        last_block_ip = block->start_offset + this_block_count;
    }

    CLEANUP:
    if (fp) {
        fclose(fp);
    }

    if (cofi_destination_block_indexes) {
        free(cofi_destination_block_indexes);
    }

    return result;

}
