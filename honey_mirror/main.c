#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "disassembly/hm_disassembly.h"
#include "code_generation/hm_code_generator.h"

int main() {
    hm_disassembly_block *blocks = NULL;
    int64_t block_count = 0;
    if (!hm_disassembly_get_blocks_from_elf("/tmp/a.out", &blocks, &block_count)) {
        printf("Failed to get blocks!\n");
        abort();
    }

    hm_code_generator_generate(blocks, block_count, "/tmp/test.s");

    free(blocks);

    return 0;
}
