#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "disassembly/hm_disassembly.h"

int main() {
    __block size_t blocks_capacity = 16;
    __block int64_t blocks_write_index = 0;
    __block hm_disassembly_block *blocks = malloc(sizeof(hm_disassembly_block) * blocks_capacity);

    hm_disassembly_get_blocks_from_elf("/Users/allison/Downloads/echo", ^(hm_disassembly_block *block) {
        if (blocks_write_index >= blocks_capacity) {
            blocks_capacity *= 2;
            hm_disassembly_block *new_blocks = realloc(blocks, sizeof(hm_disassembly_block) * blocks_capacity);
            if (!new_blocks) {
                printf("Out of memory\n");
                abort();
            }

            blocks = new_blocks;
        }

        memcpy(&blocks[blocks_write_index++], block, sizeof(hm_disassembly_block));

        printf("%lli, %p, %p (dest=%p)\n", blocks_write_index, (void *)block->start_offset, (void *)
        (block->start_offset + block->length), (void *)block->cofi_destination);
    });

    free(blocks);

    return 0;
}
