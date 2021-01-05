//
// Created by Allison Husain on 12/21/20.
//

#ifndef HONEY_MIRROR_HH_HIVE_GENERATOR_H
#define HONEY_MIRROR_HH_HIVE_GENERATOR_H
#include <stdlib.h>
#include "../disassembly/hh_disassembly.h"

int hh_hive_generator_generate(const hh_disassembly_block *sorted_blocks, int64_t block_count, const char
*hive_destination_path);

#endif //HONEY_MIRROR_HH_HIVE_GENERATOR_H
