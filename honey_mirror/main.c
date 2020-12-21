#include <stdio.h>
#include "xed-interface.h"
#include "disassembly/hm_disassembly.h"

int main() {

    hm_disassembly_get_blocks_from_elf("/Users/allison/Downloads/echo", ^(hm_disassembly_block *block) {
        printf("Block %p -> %p\n", (void *) block->start_offset, (void *) block->start_offset + block->length);
    });

    return 0;
}
