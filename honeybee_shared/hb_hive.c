//
// Created by Allison Husain on 1/4/21.
//

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <inttypes.h>

#include "hb_hive.h"
#define TAG "[" __FILE__ "] "

hb_hive *hb_hive_alloc(const char *hive_path) {
    int fd = 0;
    void *map_handle = NULL;
    hb_hive *hive = NULL;
    bool success = false;

    if (!(hive = calloc(1, sizeof(hb_hive)))) {
        printf(TAG "Out of memory\n");
        goto CLEANUP;
    }

    fd = open(hive_path, O_RDONLY);
    if (fd < 0) {
        printf(TAG "Could not open file '%s'!\n", hive_path);
        goto CLEANUP;
    }

    struct stat sb;
    int stat_result = fstat(fd, &sb);
    if (stat_result < 0) {
        printf(TAG "Could not stat file '%s'!\n", hive_path);
        goto CLEANUP;
    }

    map_handle = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (map_handle == MAP_FAILED) {
        printf(TAG "Could not mmap file '%s'!\n", hive_path);
        goto CLEANUP;
    }

    if (sb.st_size < sizeof(hb_hive_file_header)) {
        printf(TAG "File too small (cannot contain header!)\n");
        goto CLEANUP;
    }

    hb_hive_file_header *header = map_handle;
    if (header->magic != HB_HIVE_FILE_HEADER_MAGIC) {
        printf(TAG "Bad magic.\n");
        goto CLEANUP;
    }

    hive->block_count = header->block_count;
    hive->direct_map_count = header->direct_map_count;
    hive->uvip_slide = header->uvip_slide;

    uint8_t *raw_file_data_start_ptr = header->buffer;
    uint8_t *raw_file_data_end_ptr = ((uint8_t *)map_handle) + sb.st_size;

    /* copy in blocks */
    uint64_t blocks_size;
    if (__builtin_mul_overflow(hive->block_count, sizeof(uint64_t), &blocks_size)
        || __builtin_mul_overflow(blocks_size, 2 /* each block is a pair of two uint64_t */, &blocks_size)) {
        printf(TAG "Hazardous file -> block_count overflow.\n");
        goto CLEANUP;
    }
    //Bounds check for the region
    if (raw_file_data_start_ptr >= raw_file_data_end_ptr || raw_file_data_start_ptr + blocks_size >= raw_file_data_end_ptr) {
        printf(TAG "Hazardous file -> blocks buffer overrun.\n");
        goto CLEANUP;
    }

    if (!(hive->blocks = malloc(blocks_size))) {
        printf(TAG "Out of memory\n");
        goto CLEANUP;
    }

    memcpy(hive->blocks, raw_file_data_start_ptr, blocks_size);

    uint8_t *blocks_end_ptr = raw_file_data_start_ptr + blocks_size;

    /* copy in the direct map */
    uint64_t direct_map_size;
    if (__builtin_mul_overflow(hive->direct_map_count, sizeof(uint32_t), &direct_map_size)) {
        printf(TAG "Hazardous file -> direct_map_count overflow.\n");
        goto CLEANUP;
    }

    //Bounds check for the region
    if (blocks_end_ptr + direct_map_size >= raw_file_data_end_ptr) {
        printf(TAG "Hazardous file -> direct map buffer overrun.\n");
        goto CLEANUP;
    }

    if (!(hive->direct_map_buffer = malloc(direct_map_size))) {
        printf(TAG "Out of memory\n");
        goto CLEANUP;
    }

    memcpy(hive->direct_map_buffer, blocks_end_ptr, direct_map_size);

    success = true;
    CLEANUP:
    if (fd > 0) {
        close(fd);
    }

    if (map_handle && map_handle != MAP_FAILED) {
        munmap(map_handle, sb.st_size);
    }

    if (success) {
        return hive;
    } else {
        hb_hive_free(hive);
        return NULL;
    }
}

void hb_hive_free(hb_hive *hive) {
    if (!hive) {
        return;
    }

    if (hive->blocks) {
        free(hive->blocks);
        hive->blocks = NULL;
    }

    if (hive->direct_map_buffer) {
        free(hive->direct_map_buffer);
        hive->direct_map_buffer = NULL;
    }
}

void hb_hive_describe_block(hb_hive *hive, uint64_t i) {
    uint64_t index = hive->blocks[2 * i];
    uint64_t vip = hive->blocks[2 * i + 1];
    printf("Block %" PRIu64 ":\n", i);
    printf("Not-taken index = %" PRIu64 ", Taken index = %" PRIu64 ", Conditional=%" PRIu64 "\n",
           (index >> 33), (uint64_t) ((index >> 1) & ((1LLU << 31) - 1)), index & 1);
    printf("Not-taken VIP = %p, Taken VIP = %p\n", (void *) (vip >> 32), (void *) (vip & ((1LLU << 32) - 1)));
}
