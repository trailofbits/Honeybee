//
// Created by Allison Husain on 12/22/20.
//

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <mach/mach_time.h>

#include "intel-pt.h"

#include "trace_analysis/ha_session.h"

#define TAG "[" __FILE__"] "

int main() {

    /*
     * testing constants
     */
    const char *trace_path = "/tmp/ptout.1";
    const uint64_t slid_load_sideband_address = 0x55555555d000;
    const uint64_t binary_offset_sideband = 36864;


    int result;
    int fd = 0;
    void *map_handle = NULL;
    struct stat sb;
    ha_session_t session = NULL;

    fd = open(trace_path, O_RDONLY);
    if (fd < 0) {
        printf(TAG "Failed to open trace!\n");
        result = fd;
        goto CLEANUP;
    }

    if ((result = fstat(fd, &sb)) < 0) {
        printf(TAG "Failed to fstat!\n");
        goto CLEANUP;
    }

    map_handle = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (!map_handle) {
        printf(TAG "mmap failed!\n");
        result = -10;
        goto CLEANUP;
    }


    result = ha_session_alloc(&session, map_handle, sb.st_size , slid_load_sideband_address - binary_offset_sideband);
    if (result) {
        printf(TAG "Failed to start session, error=%d\n", result);
        goto CLEANUP;
    }

    uint64_t start = mach_absolute_time();
    result = ha_session_print_trace(session);
//    result = ha_session_perform_libipt_audit(session, "/tmp/a.out");
    uint64_t stop = mach_absolute_time();
    printf(TAG "Trace time = %llu ns\n", stop - start);
    if (result < 0 && result != -pte_eos) {
        printf(TAG "libipt error: %s\n", pt_errstr(pt_errcode(result)));
        goto CLEANUP;
    }

    printf(TAG "Decoding complete!\n");

    /* Completed OK, clear the result if there is any */
    result = 0;

    CLEANUP:
    if (session) {
        ha_session_free(session);
    }

    if (map_handle) {
        munmap(map_handle, sb.st_size);
    }

    if (fd) {
        close(fd);
    }

    if (result) {
        return 1;
    }

    return 0;
}