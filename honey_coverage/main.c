//
// Created by Allison Husain on 2/27/21.
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
#include <sched.h>
#include <sys/ptrace.h>
#include "../honey_analyzer/honey_analyzer.h"
#include "hc_tree_set.h"
#define TAG "[main] "
#define TAGE "[!] " TAG
#define TAGI "[*] " TAG

typedef struct {
    uint64_t hive_slide;
    uint64_t last_block;
    hc_tree_set_t edge_set;
    hc_tree_set_t block_set;
} hc_coverage_info;

static void coverage_block_reported(ha_session_t session, void *context, uint64_t unslid_ip);
static hc_tree_set_hash_type hc_uint64_t_hash(void *untyped_block);
static int hc_uint64_t_equals(void *untyped_block_a, void *untyped_block_b);

long current_clock() {
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC_RAW, &tv);

    return tv.tv_sec * 1e9 + tv.tv_nsec;
}

pid_t spawn_suspended(const char *path, char *const *argv) {
    pid_t pid = fork();
    // https://knight.sc/malware/2019/01/06/creating-suspended-processes.html
    if (pid == 0) {
        /* child */
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        //Since we do not use PTRACE_O_TRACEEXEC, this will trigger a SIGTRAP on success
        execv(path, argv);
    } else {
        /* parent */
        int status;
        waitpid(pid, &status, 0);
    }

    return pid;
}

void suspend_process(pid_t pid) {
    ptrace(PTRACE_INTERRUPT, pid, (caddr_t) 1, 0);
}

void unsuspended_process(pid_t pid) {
    ptrace(PTRACE_CONT, pid, (caddr_t) 1, 0);
}

void pin_process_to_cpu(pid_t pid, int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if (sched_setaffinity(pid, sizeof mask, &mask)) {
        perror("Couldn't pin to CPU");
    }
}

int main(int argc, const char * argv[]) {
    //XXX: Replace this with command line args
    char *hive_path = "/tmp/a.hive";
    uint64_t filter_start_address = 0x555555554000;
    uint64_t filter_stop_address =  0x6fffffffffff;

    int result;
    hc_coverage_info *coverage_info = NULL;
    ha_session_t session = NULL;
    hb_hive *hive = NULL;
    ha_capture_session_t capture_session;

    if (!(coverage_info = calloc(1, sizeof(hc_coverage_info)))
        || !(coverage_info->block_set = hc_tree_set_alloc(hc_uint64_t_hash, hc_uint64_t_equals))
        || !(coverage_info->edge_set = hc_tree_set_alloc(hc_uint64_t_hash, hc_uint64_t_equals))) {
        result = 1;
        goto CLEANUP;
    }

    if (!(hive = hb_hive_alloc(hive_path))) {
        printf(TAGE "Could not open hive at path %s\n", hive_path);
        result = 1;
        goto CLEANUP;
    }

    coverage_info->hive_slide = hive->uvip_slide;

    if ((result = ha_session_alloc(&session, hive)) < 0) {
        printf(TAGE "Could not allocate analysis session, error = %d\n", result);
        result = 1;
        goto CLEANUP;
    }

//    //XXX: Replace this with live capture
//    int fd = open("/tmp/o.pt", O_RDONLY);
//    struct stat st;
//    fstat(fd, &st);
//    uint8_t *mmap_buffer = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
//    uint8_t *terminated_buffer = malloc(st.st_size + 1);
//    memcpy(terminated_buffer, mmap_buffer, st.st_size);
//    terminated_buffer[st.st_size] = 0x55;

    if ((result = ha_capture_session_alloc(&capture_session, 0)) < 0) {
        printf(TAGE "Failed to start capture session on CPU 0, error = %d\n", result);
        result = 1;
        goto CLEANUP;
    }

    if ((result = ha_capture_session_set_global_buffer_size(capture_session, 400, 5)) < 0) {
        printf(TAGE "Failed to configure trace buffers on CPU 0, error = %d\n", result);
        result = 1;
        goto CLEANUP;
    }

    pid_t pid = spawn_suspended("/tmp/a.out", (char *const *) argv);

    ha_capture_session_range_filter filters[4];
    bzero(&filters, sizeof(ha_capture_session_range_filter) * 4);
    filters[0].enabled = 1;
    filters[0].start = filter_start_address;
    filters[0].stop = filter_stop_address;
    if ((result = ha_capture_session_configure_tracing(capture_session, pid, filters)) < 0) {
        printf(TAGE "Failed to configure tracing on CPU 0, error = %d\n", result);
        result = 1;
        goto CLEANUP;
    }

    if ((result = ha_capture_session_set_trace_enable(capture_session, 0x1, 0x1)) < 0) {
        printf(TAGE "Failed to start tracing CPU 0, error = %d\n", result);
        result = 1;
        goto CLEANUP;
    }

    unsuspended_process(pid);

    if ((result = waitpid(pid, &result, 0) < 0)) {
        printf(TAGE "Failed to wait for process, error = %d\n", result);
        result = 1;
        goto CLEANUP;
    }

    if ((result = ha_capture_session_set_trace_enable(capture_session, 0x0, 0x0)) < 0) {
        printf(TAGE "Failed to stop tracing CPU 0, error = %d\n", result);
        result = 1;
        goto CLEANUP;
    }

    uint8_t *terminated_buffer = NULL;
    uint64_t buffer_length = 0;
    if ((result = ha_capture_get_trace(capture_session, &terminated_buffer, &buffer_length)) < 0) {
        printf(TAGE "Failed to get trace buffer, error = %d\n", result);
        result = 1;
        goto CLEANUP;
    }

    if ((result = ha_session_reconfigure_with_terminated_trace_buffer(session,
                                                                      terminated_buffer,
                                                                      buffer_length,
                                                                      filter_start_address)) < 0) {
        printf(TAGE "Failed to reconfigure session, error = %d\n", result);
        result = 1;
        goto CLEANUP;
    }


    if ((result = ha_session_decode(session, coverage_block_reported, coverage_info)) < 0
        && result != - HA_PT_DECODER_END_OF_STREAM) {
        printf(TAGE "Decoder error encountered, error = %d\n", result);
        result = 1;
        goto CLEANUP;
    }

    printf(TAGI "Block count = %llu, edge count = %llu\n",
           hc_tree_set_count(coverage_info->block_set),
           hc_tree_set_count(coverage_info->edge_set));

    result = 0;

    CLEANUP:
    return result;
}

void coverage_block_reported(ha_session_t session, void *context, uint64_t unslid_ip) {
    hc_coverage_info *coverage_info = context;
    int inserted;
    uint64_t slid_ip = unslid_ip - coverage_info->hive_slide;
    //This is kinda sketchy, but since a current limitation is that we can't work over more than 4GB binaries
    //due to hive maps, this is technically safe since we are unsliding them
    uint64_t edge = coverage_info->last_block << 32 | slid_ip;
    coverage_info->last_block = slid_ip;

    inserted = hc_tree_set_insert(coverage_info->edge_set, (void *)edge);
    if (inserted == 0) {
        //Since the edge already exists, it was not inserted. Additionally, if the edge already exists, we know
        //the block already exists and so we don't need to insert it
        return;
    } else if (inserted < 0) {
        printf(TAGE "Unable to insert edge!");
        abort();
    }

    inserted = hc_tree_set_insert(coverage_info->block_set, (void *)slid_ip);
    if (inserted < 0) {
        printf(TAGE "Unable to insert block!");
        abort();
    }
}

static inline unsigned int mix_hash(unsigned int x) {
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}

static hc_tree_set_hash_type hc_uint64_t_hash(void *untyped_block) {
    uint64_t block = (uint64_t)untyped_block;
    return mix_hash(block);
}

static int hc_uint64_t_equals(void *untyped_block_a, void *untyped_block_b) {
    uint64_t a = (uint64_t)untyped_block_a;
    uint64_t b = (uint64_t)untyped_block_b;

    return a == b;
}
