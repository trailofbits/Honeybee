//
// Created by Allison Husain on 12/21/20.
//

#ifndef HONEY_MIRROR_HM_DISASSEMBLY_H
#define HONEY_MIRROR_HM_DISASSEMBLY_H

#include <stdbool.h>

/**
 * Represents a single basic block in a binary
 */
typedef struct {
    uint64_t start_offset;
    uint64_t cofi_destination;
    uint32_t length;
    uint16_t last_instruction_size;
    uint16_t instruction_category;
} hm_disassembly_block;

/**
 * A function which can be used to iterate basic blocks inside of a binary
 */
typedef void (^hm_disassembly_block_iterator)(hm_disassembly_block *block);

/**
 * Iterates the basic blocks inside of an ELF binary
 * @param path The path to the ELF binary
 * @param block_iterator The iterator block to call with each block. Note, the parameter to this function is NOT
 * owned by the iterator and may be destroyed immediately after the iterator returns.
 * @return true on success
 */
bool hm_disassembly_get_blocks_from_elf(const char *path, hm_disassembly_block_iterator block_iterator);


#endif //HONEY_MIRROR_HM_DISASSEMBLY_H
