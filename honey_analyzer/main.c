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
#include "intel-pt.h"


extern void block_decode(uint64_t unslid_ip) asm ("_block_decode");

void log_coverage(void) asm ("_log_coverage");

void log_coverage(void) {
    /* EVIL HACKS:
     * We're violating sys-v calling convention for to avoid needing to bloat the text segment of the decode loop
     * with tons of mov rdi, r12 (where where r12 is the IP in block_decode) and so we just...don't. r12 is a caller
     * saved register and so we pull it out here. Are we in hell? maybe.
     */
    uint64_t ip;
    asm("mov %%r12, %0" : "=r"(ip));
    printf("ip=%p\n", (void *) ip);
}


struct pt_query_decoder *global_decoder;
uint64_t binary_slide = 0x400000;

int handle_events(int status, uint64_t *unslid_ip) {
    while (status & pts_event_pending) {
        struct pt_event event;

        status = pt_qry_event(global_decoder, &event, sizeof(event));
        if (status < 0)
            break;

        printf("event!: %d\n", event.type);
        if (event.type == ptev_enabled) {
            *unslid_ip = event.variant.enabled.ip;
            printf("\tenable: %p\n", event.variant.enabled.ip - binary_slide);
        }
    }

    return status;
}

extern uint64_t _unslid_virtual_ip_to_text_START asm("_unslid_virtual_ip_to_text");
extern uint64_t _unslid_virtual_ip_to_text_count asm("_unslid_virtual_ip_to_text_count");

uint64_t table_search_ip(uint64_t unslid_ip) {
    uint64_t *_unslid_virtual_ip_to_text = &_unslid_virtual_ip_to_text_START;

    uint64_t left = 0;
    uint64_t right = _unslid_virtual_ip_to_text_count;

    while (left <= right) {
        uint64_t search = (left + right) / 2;
        uint64_t unslid_address = _unslid_virtual_ip_to_text[search * 2];
        if (unslid_address <= unslid_ip
            && unslid_ip < _unslid_virtual_ip_to_text[(search + 1) * 2]) {
            return _unslid_virtual_ip_to_text[search * 2 + 1];
        } else if (unslid_ip < unslid_address) {
            right = search - 1;
        } else {
            left = search + 1;
        }
    }

    return 0;
}


int take_indirect_branch_c(uint64_t *unslid_ip, uint64_t *next_code_location) {
    int status;
    uint64_t old = *unslid_ip;
    if ((status = pt_qry_indirect_branch(global_decoder, unslid_ip)) < 0
        || (status = handle_events(status, unslid_ip))) {
        return status;
    }

    *unslid_ip -= binary_slide;
    *next_code_location = table_search_ip(*unslid_ip);
    if (!*next_code_location) {
        return -1;
    }

    printf("\tvv indirect from %p to %p\n", old, *unslid_ip);

    return 0;
}

int should_take_conditional_c(uint64_t *unslid_ip, uint64_t *next_code_location_or_null) {
    int status;
    int taken = -1;
    uint64_t old = *unslid_ip;

    status = pt_qry_cond_branch(global_decoder, &taken);
    status = handle_events(status, unslid_ip);

    if (*unslid_ip != old) {
        printf("\tchanged from %p -> %p\n", old, *unslid_ip);
        *unslid_ip -= binary_slide;
        *next_code_location_or_null = table_search_ip(*unslid_ip);
    } else if (status < 0) {
        return status;
    }

    printf("\tvv taking conditional from %p: %d\n", old, taken);

    return taken;
}

#define TAG "[main] "

int main() {

    int errcode;

    int fd = 0;
    void *map_handle = NULL;
    bool success = false;

    fd = open("/tmp/trace/ptout.3", O_RDONLY);
    struct pt_config config;


    struct stat sb;
    int stat_result = fstat(fd, &sb);
    map_handle = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);

    memset(&config, 0, sizeof(config));
    config.size = sizeof(config);
    config.begin = map_handle;
    config.end = map_handle + sb.st_size;

    uint64_t ip = NULL;
    global_decoder = pt_qry_alloc_decoder(&config);
    int status;
    status = pt_qry_sync_forward(global_decoder, &ip);
    status = handle_events(status, &ip);
    if (status < 0) {
        printf("error: %s\n", pt_errstr(pt_errcode(status)));
        abort();
    }

    if (!ip) {
        status = pt_qry_indirect_branch(global_decoder, &ip);
        if (status < 0) {
            printf("error: %s\n", pt_errstr(pt_errcode(status)));
            abort();
        }
    }
    printf("Trace init complete!\n");

    block_decode(ip);
    printf("decode done\n");


    return 0;
}