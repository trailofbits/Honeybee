#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "disassembly/hh_disassembly.h"
#include "hive_generation/hh_hive_generator.h"

int main(int argc, const char * argv[]) {
    if (argc != 3) {
        printf(
                "                .' '.            __\n"
                "       .        .   .           (__\\_\n"
                "        .         .         . -{{_(|8)\n"
                "jgs       ' .  . ' ' .  . '     (__/\n\n"
                "honey_hive_generator converts an ELF binary to a 'hive' which may be used by Honeybee to accelerate "
                "Intel Processor Trace decoding inside another program.\n\n"
                "Usage:\n"
                "honey_hive_generator <input binary> <output hive location>\n"
                );
        return 1;
    }

    int result;
    hh_disassembly_block *blocks = NULL;

    const char *input_path = argv[1];
    const char *output_path = argv[2];

    //Stash our starting directory so that we can get back
    char starting_directory[PATH_MAX];
    getcwd(starting_directory, sizeof(starting_directory));

    //Generate our hive file
    int64_t block_count = 0;
    if (!hh_disassembly_get_blocks_from_elf(input_path, &blocks, &block_count)) {
        result = 2;
        printf("Failed to get blocks!\n");
        goto CLEANUP;
    }

    if ((result = hh_hive_generator_generate(blocks, block_count, output_path))) {
        result = 3;
        printf("Failed to write hive file\n");
        goto CLEANUP;
    }

    result = 0;
CLEANUP:

    free(blocks);

    return result;
}
