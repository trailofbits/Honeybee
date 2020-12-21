//
// Created by Allison Husain on 12/21/20.
//

/*
 * This file provides tools for analyzing ELF binaries using Intel XED
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "xed-interface.h"

#include "hm_disassembly.h"
#include "elf.h"

#define TAG "[" __FILE__ "] "

/**
 * Init Intel XED
 */
__attribute__((constructor))
static void intel_xed_init() {
    xed_tables_init();
}


/**
 * Is this instruction a Processor Trace qualifying change-of-flow-instruction?
 * @param xedd The decoded instruction
 * @return True if this is a COFI instruction
 */
__attribute((always_inline))
bool is_qualifying_cofi(xed_decoded_inst_t *xedd) {
    xed_category_enum_t category = xed_decoded_inst_get_category(xedd);
    switch (category) {
        case XED_CATEGORY_COND_BR:
        case XED_CATEGORY_UNCOND_BR:
        case XED_CATEGORY_CALL:
        case XED_CATEGORY_RET:
        case XED_CATEGORY_INTERRUPT:
        case XED_CATEGORY_SYSCALL:
        case XED_CATEGORY_SYSRET:
        case XED_CATEGORY_SYSTEM:
            return true;
        default:
            return false;
    }
}


bool hm_disassembly_get_blocks_from_elf(const char *path, hm_disassembly_block_iterator block_iterator) {
    int fd = 0;
    void *map_handle = NULL;
    bool success = false;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf(TAG "Could not open file '%s'!\n", path);
        goto CLEANUP;
    }
    struct stat sb;
    int stat_result = fstat(fd, &sb);
    if (stat_result < 0) {
        printf(TAG "Could not stat file '%s'!\n", path);
        goto CLEANUP;
    }

    map_handle = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (!map_handle) {
        printf(TAG "Could not mmap file '%s'!\n", path);
        goto CLEANUP;
    }

    Elf64_Ehdr *header = map_handle;
    if (sb.st_size < sizeof(Elf64_Ehdr)) {
        printf(TAG "Too small!\n");
        goto CLEANUP;
    }

    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
        printf(TAG "Bad magic!\n");
        goto CLEANUP;
    }

    if (header->e_ident[EI_CLASS] != ELFCLASS64) {
        printf(TAG "Not 64-bit!\n");
        goto CLEANUP;
    }

    if (header->e_ident[EI_DATA] != ELFDATA2LSB) {
        printf(TAG "x86_64 must be LSB");
        goto CLEANUP;
    }

    if (header->e_ident[EI_VERSION] != EV_CURRENT) {
        printf(TAG "Unsupported ELF type?\n");
        goto CLEANUP;
    }

    if (header->e_shoff > sb.st_size || header->e_shoff + sizeof(Elf64_Shdr) * header->e_shnum > sb.st_size) {
        printf(TAG "Bad section header!\n");
        goto CLEANUP;
    }


    xed_decoded_inst_t xedd;
    xed_state_t dstate;
    dstate.mmode = XED_MACHINE_MODE_LONG_64;
    hm_disassembly_block block;


    //Walk each section
    for (int i = 0; i < header->e_shnum; i++) {
        Elf64_Shdr *sh_header = (map_handle + header->e_shoff + sizeof(Elf64_Shdr) * i);
        if (sh_header->sh_offset > sb.st_size || sh_header->sh_offset + sh_header->sh_size > sb.st_size) {
            printf(TAG "Bad region defined by section header. Skipping...\n");
            continue;
        }

        //Skip non-executable sections (poor man's __TEXT filter)
        if (!(sh_header->sh_flags & SHF_EXECINSTR)) {
            continue;
        }

        //Relative pointer into this text segment
        uint8_t *text_segment = map_handle + sh_header->sh_offset;
        off_t text_segment_offset = 0;
        //A running count of where our last block started. Updated after committing each block
        uint64_t block_start = sh_header->sh_offset + text_segment_offset;

        while (text_segment_offset < sh_header->sh_size) {
            uint64_t insn_va = sh_header->sh_offset + text_segment_offset;

            //Decode the instruction
            xed_error_enum_t result;
            xed_decoded_inst_zero_set_mode(&xedd, &dstate);
            result = xed_decode(&xedd, text_segment + text_segment_offset, sb.st_size - text_segment_offset);
            if (result != XED_ERROR_NONE) {
                printf(TAG "XED decode error! %s -> %p\n", xed_error_enum_t2str(result), (void *) insn_va);
                break;
            }

            uint32_t insn_length = xed_decoded_inst_get_length(&xedd);

            if (is_qualifying_cofi(&xedd)) {
                int32_t branch_displacement = xed_decoded_inst_get_branch_displacement(&xedd);
                uint64_t cofi_destination = UINT64_MAX;
                if (branch_displacement) {
                    cofi_destination = insn_va + insn_length + branch_displacement;
                }

                block.opcode = xed_decoded_inst_get_iclass(&xedd);
                block.start_offset = block_start;
                block.length = (uint32_t) (insn_va - block_start);
                block.last_instruction_size = insn_length;
                block.cofi_destination = cofi_destination;

                block_iterator(&block);

                block_start = insn_va + insn_length;
            }

            text_segment_offset += insn_length;
        }
    }

    success = true;

    CLEANUP:
    if (map_handle) {
        munmap(map_handle, sb.st_size);
    }

    if (fd) {
        close(fd);
    }

    return success;
}