//
// Created by Allison Husain on 12/22/20.
//

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>

#include "../honey_analyzer/processor_trace/ha_pt_decoder.h"

#include "../honey_analyzer/trace_analysis/ha_session.h"
#include "unit_testing/ha_session_audit.h"

#define TAG "[" __FILE__"] "

enum execution_task {
    EXECUTION_TASK_UNKNOWN, EXECUTION_TASK_AUDIT, EXECUTION_TASK_PERFORMANCE
};

long current_clock() {
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC_RAW, &tv);

    return tv.tv_sec * 1e9 + tv.tv_nsec;
}

int main(int argc, const char * argv[]) {
    char *end_ptr = NULL;
    enum execution_task task = EXECUTION_TASK_UNKNOWN;
    char *trace_path = NULL;
    char *binary_path = NULL;
    char *hive_path = NULL;
    uint64_t slid_load_sideband_address = -1;
    uint64_t binary_offset_sideband = -1;

    int opt = 0;
    while ((opt = getopt(argc, (char *const *) argv, "aph:s:o:t:b:")) != -1) {
        switch (opt) {
            case 'a':
                task = EXECUTION_TASK_AUDIT;
                break;
            case 'p':
                task = EXECUTION_TASK_PERFORMANCE;
                break;
            case 'h':
                hive_path = optarg;
            case 's':
                slid_load_sideband_address = strtoull(optarg, &end_ptr, 16);
                break;
            case 'o':
                binary_offset_sideband = strtoull(optarg, &end_ptr, 16);
                break;
            case 't':
                trace_path = optarg;
                break;
            case 'b':
                binary_path = optarg;
                break;
            default:
            SHOW_USAGE:
                printf(
                        "                .' '.            __\n"
                        "       .        .   .           (__\\_\n"
                        "        .         .         . -{{_(|8)\n"
                        "jgs       ' .  . ' ' .  . '     (__/\n\n"
                        "honey_analyzer is a testing shim which allows for unit testing and various other debugging "
                        "and development activities.\n"
                        "Usage:\n"
                        "-a Run a correctness audit using libipt\n"
                        "-p Run a performance test\n"
                        "-h The path to the Honeybee Hive to use to decode the trace\n"
                        "-s The slid binary address according to sideband\n"
                        "-o The executable segment offset according to sideband\n"
                        "-t The Processor Trace file to decode\n"
                        "-b The binary to decode with. This is only used in libipt based tests!\n"
                );
                return 1;
        }
    }

    //Validate
    if (!trace_path || slid_load_sideband_address == -1 || binary_offset_sideband == -1
        || task == EXECUTION_TASK_UNKNOWN || !hive_path) {
        printf(TAG "Required argument missing\n");
        goto SHOW_USAGE;
    }

    if (task == EXECUTION_TASK_AUDIT && !binary_path) {
        printf(TAG "Binary path is required for audits\n");
        goto SHOW_USAGE;
    }

    /* arguments are valid */

    int result = HA_PT_DECODER_NO_ERROR;
    ha_session_t session = NULL;
    int fd = 0;
    void *trace_map_handle = NULL;
    uint64_t trace_file_size;
    uint8_t *trace_buffer = NULL;

    /* Copy in the trace file */

    fd = open(trace_path, O_RDONLY);
    if (fd < 0) {
        printf(TAG "Could not open file '%s'!\n", trace_path);
        goto CLEANUP;
    }

    struct stat sb;
    int stat_result = fstat(fd, &sb);
    if (stat_result < 0) {
        printf(TAG "Could not stat file '%s'!\n", trace_path);
        goto CLEANUP;
    }
    trace_file_size = sb.st_size;

    trace_map_handle = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (trace_map_handle == MAP_FAILED) {
        printf(TAG "Could not mmap file '%s'!\n", trace_path);
        goto CLEANUP;
    }

    if (!(trace_buffer = malloc(trace_file_size + 1 /* Required for ha_session and ha_decoder */))) {
        printf(TAG "Out of memory\n");
        goto CLEANUP;
    }
    memcpy(trace_buffer, trace_map_handle, trace_file_size);

    /* Setup the session */

    uint64_t trace_base_address = slid_load_sideband_address - binary_offset_sideband;
    if ((result = ha_session_alloc(&session, hive_path)) < 0
        || (result = ha_session_reconfigure_with_rw_trace_buffer(session, trace_buffer, trace_file_size,
                                                                 trace_base_address))) {
        printf(TAG "Failed to start session, error=%d\n", result);
        goto CLEANUP;
    }

    /* Execute our operation */

    uint64_t start = current_clock();
    uint64_t stop;
    if (task == EXECUTION_TASK_AUDIT) {
        result = ha_session_audit_perform_libipt_audit(session, binary_path, trace_buffer, trace_file_size);
        stop = current_clock();

        if (result < 0) {
            printf(TAG "Test failure = %d\n", result);
        } else {
            printf(TAG "Test pass!\n");
        }
    } else {
        result = ha_session_print_trace(session);
        stop = current_clock();

        if (result < 0 && result != -HA_PT_DECODER_END_OF_STREAM) {
            printf(TAG "decode error = %d\n", result);
        } else {
            printf(TAG "Decode success!\n");
            result = 0;
        }
    }

    printf(TAG "Execute time = %"PRIu64" ns\n", stop - start);

    /* Completed OK, clear the result if there is any */
    CLEANUP:
    if (session) {
        ha_session_free(session);
    }

    if (fd > 0) {
        close(fd);
    }

    if (trace_map_handle && trace_map_handle != MAP_FAILED) {
        munmap(trace_map_handle, trace_file_size);
    }

    if (trace_buffer) {
        free(trace_buffer);
    }

    return -result;
}