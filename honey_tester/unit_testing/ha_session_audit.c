//
// Created by Allison Husain on 12/30/20.
//

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "intel-pt.h"

#include "ha_session_audit.h"
#include "../../honey_analyzer/trace_analysis/ha_session_internal.h"
#include "../../honey_analyzer/trace_analysis/ha_mirror_utils.h"
#include "../../honey_analyzer/ha_debug_switch.h"

#define TAG "[" __FILE__ "] "



typedef struct {
    struct pt_block_decoder *block_decoder;
    uint64_t last_libipt_ip;
    enum ha_session_audit_status status;
    uint64_t honey_blocks_passed;
} audit_extra;

static void libipt_audit_on_block(ha_session_t session, uint64_t mirror_unslid_ip) {
    audit_extra *extra = session->extra_context;
    if (extra->status) {
        //We don't actually have a way to abort a trace in progress, however we will refuse to continue the test so
        // as to not destroy the original error
        return;
    }

    struct pt_block_decoder *block_decoder = extra->block_decoder;

    int result = 0;
    struct pt_block block;
    bzero(&block, sizeof(struct pt_block));

    while (block.ninsn == 0) {
        FUP_TRY_AGAIN:
        result = pt_blk_next(block_decoder, &block, sizeof(block));
        while (result & pts_event_pending) {
            if (result < 0) {
                printf(TAG "Testing failed, libipt event decode error: %d\n", result);
                extra->status = -HA_SESSION_AUDIT_TEST_LIBIPT_ERROR;
                return;
            }
            struct pt_event event;
            result = pt_blk_event(block_decoder, &event, sizeof(event));
        }

        if (result < 0) {
            printf(TAG "Testing failed, libipt block decode error: %d\n", result);
            extra->status = -HA_SESSION_AUDIT_TEST_LIBIPT_ERROR;
            return;
        }
    }

    uint64_t libipt_unslid = block.ip - session->binary_slide;
    if (mirror_unslid_ip == libipt_unslid) {
        //We store the last block IP to account for libipt's special handling of FUPs and its choice to split blocks
        extra->last_libipt_ip = libipt_unslid;
        extra->honey_blocks_passed++;
#if HA_ENABLE_BLOCK_LEVEL_LOGS
        printf(TAG "PASS! mirror = %p, libipt = %p.\n", (void *)mirror_unslid_ip, (void *)libipt_unslid);
#endif
    } else if (extra->last_libipt_ip && ha_mirror_utils_convert_unslid_to_offset(libipt_unslid)
        == ha_mirror_utils_convert_unslid_to_offset(extra->last_libipt_ip)) {
        //We have a split block
#if HA_ENABLE_BLOCK_LEVEL_LOGS
        printf(TAG "\tDetected libipt splitting last block %p to %p due to an FUP. Trying again!\n",
               (void *)extra->last_libipt_ip, (void *)libipt_unslid);
#endif
        extra->last_libipt_ip = 0; //clear so we don't loop
        goto FUP_TRY_AGAIN;
    } else {
        printf(TAG "*** AUDIT FAILED ***\n");
        printf(TAG "mirror = %p, libipt = %p [honey_blocks = %llu]\n",
               (void *)mirror_unslid_ip, (void *)libipt_unslid, extra->honey_blocks_passed);
        extra->status = -HA_SESSION_AUDIT_TEST_INCORRECT_RESULT;
//        asm("ud2");
    }
}

int ha_session_audit_perform_libipt_audit(ha_session_t session, const char *binary_path) {
    int result = 0;
    int fd = 0;
    struct stat sb;
    struct pt_block_decoder *block_decoder = NULL;
    const char *map_handle = NULL;
    audit_extra *extra = NULL;

    //Map in the binary for libipt
    fd = open(binary_path, O_RDONLY);
    if (fd < 0) {
        printf(TAG "Failed to open binary!\n");
        result = -HA_SESSION_AUDIT_TEST_INIT_FAILED;
        goto CLEANUP;
    }

    if ((result = fstat(fd, &sb)) < 0) {
        printf(TAG "Failed to fstat!\n");
        result = -HA_SESSION_AUDIT_TEST_INIT_FAILED;
        goto CLEANUP;
    }

    map_handle = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (map_handle == MAP_FAILED) {
        printf(TAG "mmap failed!\n");
        result = -HA_SESSION_AUDIT_TEST_INIT_FAILED;
        goto CLEANUP;
    }

    extra = calloc(1, sizeof(audit_extra));
    if (!extra) {
        result = -11;
        goto CLEANUP;
    }

    /* libipt configuration */
    uint8_t *trace_ptr = NULL;
    uint64_t trace_length = 0;
    ha_pt_decoder_internal_get_trace_buffer(session->decoder, &trace_ptr, &trace_length);
    struct pt_config config;
    config.size = sizeof(struct pt_config);
    config.begin = trace_ptr;
    config.end = trace_ptr + trace_length;
    //Stop on all control flow in order to duplicate the behavior of mirrors
    config.flags.variant.block.end_on_jump = 1;
    config.flags.variant.block.end_on_call = 1;

    block_decoder = pt_blk_alloc_decoder(&config);

    if (!block_decoder) {
        result = -HA_SESSION_AUDIT_TEST_INIT_FAILED;
        goto CLEANUP;
    }

    struct pt_image *image_unowned = pt_blk_get_image(block_decoder);
    if ((result = pt_image_add_file(image_unowned, binary_path, 0x00, sb.st_size, NULL, session->binary_slide)) < 0
        || (result = pt_blk_sync_forward(block_decoder)) < 0) {
        result = -HA_SESSION_AUDIT_TEST_INIT_FAILED;
        goto CLEANUP;
    }


    //Stash the block_decoder pointer so the logger function can access it
    extra->block_decoder = block_decoder;
    session->extra_context = extra;

    //Kickoff mirror decoding from our side
    session->on_block_function = libipt_audit_on_block;
    result = ha_mirror_block_decode(session);

    //Figure out which result we want to end with. We want the EARLIEST error.
    if (extra->status != HA_SESSION_AUDIT_TEST_PASS) {
        result = extra->status;
        goto CLEANUP;
    } else if (result < 0 && result != -HA_PT_DECODER_END_OF_STREAM) {
        result = -HA_SESSION_AUDIT_TEST_HONEYBEE_ERROR;
        goto CLEANUP;
    }

    result = HA_SESSION_AUDIT_TEST_PASS;

    CLEANUP:
    if (block_decoder) {
        pt_blk_free_decoder(block_decoder);
    }

    if (fd >= 0) {
        close(fd);
    }

    if (extra) {
        free(extra);
    }

    return result;
}

