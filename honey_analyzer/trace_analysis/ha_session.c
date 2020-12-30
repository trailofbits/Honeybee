//
// Created by Allison Husain on 12/23/20.
//
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "ha_session.h"
#include "ha_mirror_utils.h"
#include "../processor_trace/ha_pt_decoder.h"

#define TAG "[" __FILE__ "] "

#define DEBUG_LOGGING 1
#define FLAG_DID_OVERRIDE_IP (1<<30)


typedef struct internal_ha_session {
    /**
     * The function called by this session when a block is decoded
     * NOTE: DO NOT MOVE THIS WITHOUT UPDATING ha_block_decode_thunks !!!
     */
    ha_mirror_on_block_function *on_block_function;

    /**
     * The session's decoder
     */
    ha_pt_decoder_t decoder;

    /**
     * The (for now) global slide. This will be subtracted from all trace addresses to get the un-slid value
     */
    uint64_t binary_slide;

    /**
     * An addition field which custom decoders can use
     */
    void *extra_context;
} ha_session;

/* forward declarations */
static int handle_events(ha_session *session, int status, uint64_t *override_ip);

int ha_session_alloc(ha_session_t *session_out, const char *trace_path, uint64_t binary_slide) {
    int result = 0;

    if (!(session_out && trace_path)) {
        //Invalid argument
        result = -1;
        goto CLEANUP;
    }

    ha_session *session = calloc(1, sizeof(ha_session));
    if (!session) {
        result = -2;
        goto CLEANUP;
    }

    session->binary_slide = binary_slide;

    session->decoder = ha_pt_decoder_alloc(trace_path);
    if (!session->decoder) {
        result = -3;
        goto CLEANUP;
    }

    /* POST INIT -- all structure objects MUST be created before this point */

    result = ha_pt_decoder_sync_forward(session->decoder);
    if (result < 0) {
        goto CLEANUP;
    }

    //init complete -- clear any status code since we're okay
    result = 0;

    CLEANUP:
    if (result) {
        //We hit some error, tear everything down
        //_dealloc is safe and works on half generated structures
        ha_session_free(session);
    } else {
        //Pass back the created structure
        *session_out = session;
    }

    return result;
}

void ha_session_free(ha_session_t session) {
    if (!session) {
        return;
    }

    if (session->decoder) {
        ha_pt_decoder_free(session->decoder);
        session->decoder = NULL;
    }

    free(session);
}

int ha_session_take_indirect_branch(ha_session_t session, uint64_t *override_ip, uint64_t *override_code_location) {
    int result = ha_pt_decoder_cache_query_indirect(session->decoder, override_ip);
    if (result < 0) {
        return result;
    }

    *override_ip -= session->binary_slide;
    *override_code_location = ha_mirror_utils_convert_unslid_to_code(*override_ip);
    if (!*override_code_location) {
        return -1;
    }


#if DEBUG_LOGGING
    if (result == 1) {
        printf(TAG "\tasync event update, switching to %p\n", (void *)*override_ip);
    } else {
        printf(TAG "\tvv indirect from to %p\n", (void *)*override_ip);
    }
#endif

    return 0;
}

int ha_session_take_conditional(ha_session_t session, uint64_t *override_ip, uint64_t *override_code_location) {
    int taken = ha_pt_decoder_cache_query_tnt(session->decoder, override_ip);
    if (taken == 2) {
        //Override
        *override_ip -= session->binary_slide;
        *override_code_location = ha_mirror_utils_convert_unslid_to_code(*override_ip);

        if (!*override_code_location) {
            return -1;
        }

#if DEBUG_LOGGING
        printf(TAG "\tasync event update, switching to %p\n", (void *)*override_ip);
#endif

        return 0x3;
    }


#if DEBUG_LOGGING
    printf(TAG "\tvv taking conditional: %d\n", taken);
#endif

    return taken;
}

//MARK: - Custom trace implementations

int ha_session_generate_coverage(ha_session_t session) {
    //FIXME: Not implemented
    abort();
}

//static void libipt_audit_on_block(ha_session_t session, uint64_t mirror_unslid_ip) {
//    struct pt_block_decoder *block_decoder = session->extra_context;
//    int result = 0;
//    struct pt_block block;
//    bzero(&block, sizeof(struct pt_block));
//    while (block.ninsn == 0) {
//        result = pt_blk_next(block_decoder, &block, sizeof(block));
//        while (result & pts_event_pending) {
//            if (result < 0) {
//                printf(TAG "Testing failed, libipt event decode error: %d\n", result);
//                abort();
//            }
//            struct pt_event event;
//            result = pt_blk_event(block_decoder, &event, sizeof(event));
//        }
//
//        if (result < 0) {
//            printf(TAG "Testing failed, libipt block decode error: %d\n", result);
//            abort();
//        }
//    }
//
//    uint64_t libipt_unslid = block.ip - session->binary_slide;
//    if (mirror_unslid_ip == libipt_unslid) {
//        printf(TAG "PASS! mirror = %p, libipt = %p.\n", (void *)mirror_unslid_ip, (void *)libipt_unslid);
//    } else {
//        printf(TAG "*** AUDIT FAILED ***\n");
//        printf(TAG "mirror = %p, libipt = %p. Aborting!\n", (void *)mirror_unslid_ip, (void *)libipt_unslid);
//        abort();
//    }
//}
//
//int ha_session_perform_libipt_audit(ha_session_t session, const char *binary_path) {
//    int result = 0;
//    int fd = 0;
//    struct stat sb;
//    struct pt_block_decoder *block_decoder = NULL;
//
//    fd = open(binary_path, O_RDONLY);
//    if (fd < 0) {
//        printf(TAG "Failed to open binary!\n");
//        result = fd;
//        goto CLEANUP;
//    }
//
//    if ((result = fstat(fd, &sb)) < 0) {
//        printf(TAG "Failed to fstat!\n");
//        goto CLEANUP;
//    }
//
//    close(fd);
//    fd = -1;
//
//    /* libipt configuration */
//    struct pt_config config;
//    memcpy(&config, pt_qry_get_config(session->decoder), sizeof(struct pt_config));
//    //Stop on all control flow in order to duplicate the behavior of mirrors
//    config.flags.variant.block.end_on_jump = 1;
//    config.flags.variant.block.end_on_call = 1;
//    block_decoder = pt_blk_alloc_decoder(&config);
//
//    if (!block_decoder) {
//        result = 1;
//        goto CLEANUP;
//    }
//
//    struct pt_image *image_unowned = pt_blk_get_image(block_decoder);
//
//    if ((result = pt_image_add_file(image_unowned, binary_path, 0x00, sb.st_size, NULL, session->binary_slide)) < 0
//        || (result = pt_blk_sync_forward(block_decoder)) < 0) {
//        goto CLEANUP;
//    }
//
//    //Stash the block_decoder pointer so the logger function can access it
//    session->extra_context = block_decoder;
//
//    //Kickoff mirror decoding from our side
//    session->on_block_function = libipt_audit_on_block;
//    result = ha_mirror_block_decode(session, session->initial_unslid_ip);
//
//    result = 0;
//
//    CLEANUP:
//    if (block_decoder) {
//        pt_blk_free_decoder(block_decoder);
//    }
//
//    if (fd >= 0) {
//        close(fd);
//    }
//
//    return result;
//}

static void print_trace(ha_session_t session, uint64_t unslid_ip) {
#if DEBUG_LOGGING
    printf(TAG "logger: %p\n", (void *)unslid_ip);
#endif
}

int ha_session_print_trace(ha_session_t session) {
    session->on_block_function = print_trace;
#if DEBUG_LOGGING
    printf(TAG "--BEGIN TRACE DECODE--\n");
#endif
    return ha_mirror_block_decode(session);
}
