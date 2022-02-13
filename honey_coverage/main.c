//
// Created by Allison Husain on 2/27/21.
//

#define _GNU_SOURCE
#define _POSIX_SOURCE

#include <sys/wait.h>
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
#include <sys/personality.h>

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

static int hc_tree_iterate_print(void *element, void *context);

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
        //disable ASLR for child
        int old, rc;
        old = personality(0xffffffff); /* Fetch old personality. */
        rc = personality(old | ADDR_NO_RANDOMIZE);
        if (-1 == rc) {
            perror("personality");
        }

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

void unsuspend_process(pid_t pid) {
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
    if (argc < 7
        || strncmp(argv[4], "--", 2) != 0) {
        printf("Usage: %s <hive path> <filter start> <filter stop> -- <target binary> [target args]\n"
               "This program outputs a set of all basic blocks and edge hashes visited in the following format:\n"
               "<block count>\n"
               "<edge count>\n"
               "...<block IPs in base 10, one per line>...\n"
               "...<edge hashes in base 10, one per line>...\n",
               argv[0]);
        return 1;
    }

    const char *hive_path = argv[1];
    uint64_t filter_start_address = strtoull(argv[2], NULL, 0);
    uint64_t filter_stop_address = strtoull(argv[3], NULL, 0);
    const char *target_binary = argv[5];
    const char **target_args = argv + 5; /* we need to include the target binary in target argv */

    int result = 1;
    hc_coverage_info *coverage_info = NULL;
    ha_session_t session = NULL;
    hb_hive *hive = NULL;
    ha_capture_session_t capture_session = NULL;

    if (!(coverage_info = calloc(1, sizeof(hc_coverage_info)))
        || !(coverage_info->block_set = hc_tree_set_alloc(hc_uint64_t_hash, hc_uint64_t_equals))
        || !(coverage_info->edge_set = hc_tree_set_alloc(hc_uint64_t_hash, hc_uint64_t_equals))) {
        goto CLEANUP;
    }

    if (!(hive = hb_hive_alloc(hive_path))) {
        printf(TAGE "Could not open hive at path %s\n", hive_path);
        goto CLEANUP;
    }

    coverage_info->hive_slide = hive->uvip_slide;

    if ((result = ha_session_alloc(&session, hive)) < 0) {
        printf(TAGE "Could not allocate analysis session, error = %d\n", result);
        goto CLEANUP;
    }

    if ((result = ha_capture_session_alloc(&capture_session, 0)) < 0) {
        printf(TAGE "Failed to start capture session on CPU 0, error = %d\n", result);
        goto CLEANUP;
    }

    if ((result = ha_capture_session_set_global_buffer_size(capture_session, 400, 5)) < 0) {
        printf(TAGE "Failed to configure trace buffers on CPU 0, error = %d\n", result);
        goto CLEANUP;
    }

    pid_t pid = spawn_suspended(target_binary, (char *const *) target_args);
    pin_process_to_cpu(pid, 0);
//    printf(TAGI "Spawned process %d\n", pid);

    ha_capture_session_range_filter filters[4];
    bzero(&filters, sizeof(ha_capture_session_range_filter) * 4);
    filters[0].enabled = 1;
    filters[0].start = filter_start_address;
    filters[0].stop = filter_stop_address;
    if ((result = ha_capture_session_configure_tracing(capture_session, pid, filters)) < 0) {
        printf(TAGE "Failed to configure tracing on CPU 0, error = %d\n", result);
        goto CLEANUP;
    }

    if ((result = ha_capture_session_set_trace_enable(capture_session, 0x1, 0x1)) < 0) {
        printf(TAGE "Failed to start tracing CPU 0, error = %d\n", result);
        goto CLEANUP;
    }

    unsuspend_process(pid);

    if ((result = waitpid(pid, &result, 0) < 0)) {
        printf(TAGE "Failed to wait for process, error = %d\n", result);
        goto CLEANUP;
    }

    if ((result = ha_capture_session_set_trace_enable(capture_session, 0x0, 0x0)) < 0) {
        printf(TAGE "Failed to stop tracing CPU 0, error = %d\n", result);
        goto CLEANUP;
    }

    uint8_t *terminated_buffer = NULL;
    uint64_t buffer_length = 0;
    if ((result = ha_capture_session_get_trace(capture_session, &terminated_buffer, &buffer_length)) < 0) {
        printf(TAGE "Failed to get trace buffer, error = %d\n", result);
        goto CLEANUP;
    }

    if ((result = ha_session_reconfigure_with_terminated_trace_buffer(session,
                                                                      terminated_buffer,
                                                                      buffer_length,
                                                                      filter_start_address)) < 0) {
        printf(TAGE "Failed to reconfigure session, error = %d\n", result);
        goto CLEANUP;
    }


    if ((result = ha_session_decode(session, coverage_block_reported, coverage_info)) < 0
        && result != -HA_PT_DECODER_END_OF_STREAM) {
        printf(TAGE "Decoder error encountered, error = %d\n", result);
        goto CLEANUP;
    }

    /*
     * output format:
     * block set count
     * edge set count
     * [[block set elements]]
     * [[edge set elements ]]
     */

    printf("%llu\n%llu\n",
           hc_tree_set_count(coverage_info->block_set),
           hc_tree_set_count(coverage_info->edge_set));

    if ((result = hc_tree_set_iterate_all(coverage_info->block_set, hc_tree_iterate_print,
                                          (void *) hive->uvip_slide)) < 0) {
        printf(TAGE "Couldn't iterate block set");
        goto CLEANUP;
    }

    if ((result = hc_tree_set_iterate_all(coverage_info->edge_set, hc_tree_iterate_print, 0)) < 0) {
        printf(TAGE "Couldn't iterate edge set");
        goto CLEANUP;
    }

    result = 0;

    CLEANUP:
    if (coverage_info) {
        if (coverage_info->block_set) {
            hc_tree_set_free(coverage_info->block_set);
        }

        if (coverage_info->edge_set) {
            hc_tree_set_free(coverage_info->edge_set);
        }

        free(coverage_info);
    }

    if (session) {
        ha_session_free(session);
    }

    if (capture_session) {
        ha_capture_session_free(capture_session);
    }

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

static int hc_tree_iterate_print(void *element, void *context) {
    uint64_t slide = (uint64_t) context;
    printf("%"PRIu64"\n", ((uint64_t) element) + slide);
    return 0;
}