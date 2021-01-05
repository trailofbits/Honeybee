//
// Created by Allison Husain on 1/4/21.
//

#ifndef HB_HIVE_H
#define HB_HIVE_H

#include <stdlib.h>
#include <stdint.h>

/** HONEYBEE (little endian) :) */
#define HB_HIVE_FILE_HEADER_MAGIC (0x45454259454E4F48)
/** Is this index block a conditional jump? */
#define HB_HIVE_FLAG_IS_CONDITIONAL (1)
/** Is this jump index target an indirect jump? */
#define HB_HIVE_FLAG_INDIRECT_JUMP_INDEX_VALUE ((1LLU<<31) - 1) //31 bits of ones

/**
 * This is the header of the Honeybee Hive file
 */
typedef struct {
    /**
     * The file magic
     * 0x45454259454E4F48 which is HONEYBEE (little endian)
     */
    uint64_t magic;

    /**
     * The number of 64-bit pairs in the blocks buffer
     */
    uint64_t block_count;
    /**
     * The value by which virtual IPs in blocks and the direct map are slid by. This can be thought of as a bias
     * value for an unsigned integer.
     */
    uint64_t uvip_slide;

    /**
     * The number of 32-bit elements in the direct map buffer
     */
    uint64_t direct_map_count;

    /**
     * A zero length array used to provide a pointer after the header. This is not a real field, this is for convenience
     */
    uint8_t buffer[0];

    /* blocks -- uint64_t */

    //Since we know the number of blocks, we can just assume that everything after blocks is just map

    /* slid virtual address to block index -- uint32_t */
} hb_hive_file_header;

/**
 * Each block is a pair of 64-bit packet values
 */
typedef struct {
    /**
     * This is a packed field which holds the indices of the next block(s) as well as information about the block.
     * The conditional flag should be tested for using HB_HIVE_FLAG_IS_CONDITIONAL.
     * If this block contains an indirect jump, the index for a branch will be HB_HIVE_FLAG_INDIRECT_JUMP_INDEX_VALUE.
     *
     * [{31 bits of not-taken}, {zero}][{31 bits of taken}, {1 bit conditional flag}]
     */
    uint64_t packed_indices;

    /**
     * This is a packed field which holds the slid virtual instruction pointers for the block(s) after this one.
     * Holding slid VIPs in 32-bits is technically okay, even on a 64-bit OS, since our decoding stategy breaks down
     * as a result of the direct map on binaries >=4GB (since the direct map would necessarily be 16GB).
     *
     * [{32 bits of not-taken uVIP}][{32 bits of taken uVIP}]
     */
    uint64_t packed_uvips;
} hm_block;


typedef struct {
    /**
     * A pointer to a buffer of blocks
     * This can also be read as an hm_block or simply stride-d
     */
    uint64_t *blocks;

    /**
     * The number of pairs (or just hm_blocks) in the blocks buffer
     */
    uint64_t block_count;

    /**
     * This bias value/positive slide for uVIPs. This is also the amount that values must be slid negatively to get
     * the index into the direct map buffer
     */
    uint64_t uvip_slide;

    /**
     * The map of slid virtual instruction pointers to block indices.
     * To calculate the index into the buffer, use the hb_hive_virtual_address_to_block_index function
     */
    uint32_t *direct_map_buffer;

    /**
     * The number of uint32_t elements in the direct map. The map is indexed by each byte of the binary being
     * assigned an index, starting from zero.
     */
    uint64_t direct_map_count;
} hb_hive;


/**
 * Load a hive from disk and parse it
 * @param hive_path The path to the honeybee hive file
 * @return NULL if parsing failed for any reason
 */
hb_hive *hb_hive_alloc(const char *hive_path);

/**
 * Frees a hive and all of its contents
 */
void hb_hive_free(hb_hive *hive);

/**
 * Print a description of a given block to the console
 */
void hb_hive_describe_block(hb_hive *hive, uint64_t i);

/**
 * Get the block index for a given unslid virtual address
 * @param hive The hive corresponding to the binary being traced
 * @param virtual_address The virtual address as it came from the trace
 * @return The index or -1 if the virtual address is not mapped in this hive
 */
static inline int64_t hb_hive_virtual_address_to_block_index(hb_hive *hive, uint64_t virtual_address) {
    uint64_t map_index = virtual_address - hive->uvip_slide;
    if (map_index >= hive->direct_map_count) {
        return -1;
    }
    return hive->direct_map_buffer[map_index];
}

#endif //HB_HIVE_H
