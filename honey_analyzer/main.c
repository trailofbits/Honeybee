//
// Created by Allison Husain on 12/22/20.
//

#include "intel-pt.h"

extern void block_decode(void) asm ("_block_decode");
int main() {

    pt_insn_next(0,0,0);

    block_decode();

    return 0;
}