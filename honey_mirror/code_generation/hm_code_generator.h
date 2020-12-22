//
// Created by Allison Husain on 12/21/20.
//

#ifndef HONEY_MIRROR_HM_CODE_GENERATOR_H
#define HONEY_MIRROR_HM_CODE_GENERATOR_H
#include <stdlib.h>
#include "../disassembly/hm_disassembly.h"

int hm_code_generator_generate(const hm_disassembly_block *sorted_blocks, int64_t block_count, const char
*code_destination_path);

#endif //HONEY_MIRROR_HM_CODE_GENERATOR_H
