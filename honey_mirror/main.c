#include <stdio.h>
#include "xed-interface.h"

int main() {
    xed_machine_mode_enum_t mmode;
    xed_address_width_enum_t stack_addr_width;
    xed_bool_t long_mode = 1;
    // create the decoded instruction, and fill in the machine mode (dstate)
    // make up a simple 2Byte instruction to decode
    unsigned int bytes = 0;
    unsigned char itext[15] = { 0xf, 0x85, 0x99, 0x00, 0x00, 0x00 };
    // initialize the XED tables -- one time.
    xed_tables_init();
    // The state of the machine -- required for decoding
    if (long_mode) {
        mmode=XED_MACHINE_MODE_LONG_64;
        stack_addr_width = XED_ADDRESS_WIDTH_64b;
    }
    else {
        mmode=XED_MACHINE_MODE_LEGACY_32;
        stack_addr_width = XED_ADDRESS_WIDTH_32b;
    }
    // This is a test of error handling. I vary the instuction length from
    // 0 bytes to 15 bytes.  Normally, you should send in 15 bytes of itext
    // unless you are near the end of a page and don't want to take a page
    // fault or tlb miss. Note, you have to reinitialize the xedd each time
    // you try to decode in to it.
    // Try different instruction lengths to see when XED recognizes an
    // instruction as valid.
    for(bytes = 0;bytes<=15;bytes++) {
        xed_error_enum_t xed_error;
        xed_decoded_inst_t xedd;
        xed_decoded_inst_zero(&xedd);
        xed_decoded_inst_set_mode(&xedd, mmode, stack_addr_width);
        xed_error = xed_decode(&xedd,
                               XED_STATIC_CAST(const xed_uint8_t*,itext),
                               bytes);
        printf("%d %s\n",(int)bytes, xed_error_enum_t2str(xed_error));
    }
    return 0;
}
