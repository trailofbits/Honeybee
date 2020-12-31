//
// Created by Allison Husain on 12/22/20.
//

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <mach/mach_time.h>

#include "processor_trace/ha_pt_decoder.h"

#include "trace_analysis/ha_session.h"
#include "testing/ha_session_audit.h"

#define TAG "[" __FILE__"] "

int main(int argc, const char * argv[]) {
//    printf(TAG "honey_analyzer testing shim :)\n");
//    int opt = 0;
//    while ((opt = getopt(argc, argv, "apsotb"))) {
//        switch (opt) {
//            case 'a':
//                break;
//            case 'p':
//                break;
//            case 's':
//                break;
//            case 'o':
//                break;
//            case 't':
//                break;
//            case 'b':
//                break;
//            default:
//                printf(
//                        "Usage:\n"
//                        "-a Run a correctness audit using libipt\n"
//                        "-p Run a performance test\n"
//                        "-s The slid binary address according to sideband\n"
//                        "-o The binary offset according to sideband\n"
//                        "-t The Processor Trace file to decode\n"
//                        "-b The binary to decode with. This is only used in libipt based tests!\n"
//                );
//                return 1;
//        }
//    }

//    if (argc != 5) {
//        printf()
//    }
    /*
     * testing constants
     */
    const char *trace_path = "/tmp/ptout.1";
    const uint64_t slid_load_sideband_address = 0x55555555d000;
    const uint64_t binary_offset_sideband = 36864;

    int result = HA_PT_DECODER_NO_ERROR;
    ha_session_t session = NULL;

    result = ha_session_alloc(&session, trace_path , slid_load_sideband_address - binary_offset_sideband);
    if (result) {
        printf(TAG "Failed to start session, error=%d\n", result);
        goto CLEANUP;
    }

    uint64_t start = mach_absolute_time();
//    result = ha_session_print_trace(session);
    result = ha_session_audit_perform_libipt_audit(session, "/tmp/a.out");
    uint64_t stop = mach_absolute_time();
    printf(TAG "Trace time = %llu ns\n", stop - start);
    if (result < 0 && result != -HA_PT_DECODER_END_OF_STREAM) {
        printf("decode error = %d\n", result);
    }
    printf(TAG "Decoding complete!\n");

    /* Completed OK, clear the result if there is any */
    CLEANUP:
        ha_session_free(session);
    return 0;
}