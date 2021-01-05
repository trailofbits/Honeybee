//
// Created by Allison Husain on 12/21/20.
//

#ifndef HONEY_MIRROR_HH_DISASSEMBLY_H
#define HONEY_MIRROR_HH_DISASSEMBLY_H

#include <stdbool.h>
#include <stdint.h>

/**
 * Represents a single basic block in a binary
 */
typedef struct {
    uint64_t start_offset;
    uint64_t cofi_destination;
    uint32_t length;
    uint16_t last_instruction_size;
    uint16_t instruction_category;
} hh_disassembly_block;

/**
 * Iterates the basic blocks inside of an ELF binary
 * @param path The path to the ELF binary
 * @param blocks The location to place a pointer to a buffer of blocks. You are responsible for freeing this buffer.
 * @param blocks_count The location to place the number of blocks in the blocks buffer
 * @return true on success
 */
bool hh_disassembly_get_blocks_from_elf(const char *path, hh_disassembly_block **blocks, int64_t *blocks_count);


#endif //HONEY_MIRROR_HH_DISASSEMBLY_H
