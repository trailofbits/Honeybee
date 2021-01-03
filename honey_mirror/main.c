#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "disassembly/hm_disassembly.h"
#include "code_generation/hm_code_generator.h"

int main(int argc, const char * argv[]) {
    if (argc != 4) {
        printf(
                "                .' '.            __\n"
                "       .        .   .           (__\\_\n"
                "        .         .         . -{{_(|8)\n"
                "jgs       ' .  . ' ' .  . '     (__/\n\n"
                "honey_mirror converts an ELF binary to a 'mirror' which may be used by Honeybee to accelerate Intel "
                "Processor Trace decoding inside another program.\n\n"
                "Usage:\n"
                "honey_mirror <input binary> <output shared library location> <honeybee build directory>\n"
                );
        return 1;
    }

    int result;
    hm_disassembly_block *blocks = NULL;

    const char *input_path = argv[1];
    const char *output_binary_path = argv[2];
    const char *honeybee_build_path = argv[3];

    //Stash our starting directory so that we can get back
    char starting_directory[PATH_MAX];
    getcwd(starting_directory, sizeof(starting_directory));

    //Generate our mirror assembly file
    int64_t block_count = 0;
    if (!hm_disassembly_get_blocks_from_elf(input_path, &blocks, &block_count)) {
        result = 2;
        printf("Failed to get blocks!\n");
        goto CLEANUP;
    }

    if ((result = hm_code_generator_generate(blocks, block_count, "/tmp/mirror.S"))) {
        result = 3;
        printf("Failed to write mirror file\n");
        goto CLEANUP;
    }

    //Generate a new honey_analysis binary
    if ((result = chdir(honeybee_build_path))) {
        result = 3;
        printf("Could not chdir to build directory %s\n", honeybee_build_path);
        goto CLEANUP;
    }

    if ((result = system("cmake --build cmake-build-debug --target honey_analyzer"))) {
        result = 4;
        printf("cmake build failed\n");
        goto CLEANUP;
    }

    //Move the generate binary to the target location
    if ((result = chdir(starting_directory))) {
        result = 5;
        printf("Could not return to original directory %s\n", starting_directory);
        goto CLEANUP;
    }

    char source_path[PATH_MAX];
    const char *source_path_sprintf;
#if __APPLE__
    source_path_sprintf = "%s/cmake-build-debug/libhoney_analyzer.dylib";
#else
    source_path_sprintf = "%s/cmake-build-debug/libhoney_analyzer.so";
#endif
    snprintf(source_path, sizeof(source_path), source_path_sprintf, honeybee_build_path);

    if ((result = rename(source_path, output_binary_path))) {
        result = 6;
        printf("Could not move output binary!\n");
        goto CLEANUP;
    }

    result = 0;
CLEANUP:

    free(blocks);

    return result;
}
