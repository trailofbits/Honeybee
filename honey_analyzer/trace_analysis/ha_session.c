//
// Created by Allison Husain on 12/23/20.
//
#include <stdlib.h>
#include <stdio.h>

#include "ha_session.h"
#include "ha_session_internal.h"
#include "ha_mirror_utils.h"
#include "../ha_debug_switch.h"

#define TAG "[" __FILE__ "] "

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

int ha_session_take_indirect_branch(ha_session_t session, uint64_t *override_ip) {
    int result = ha_pt_decoder_cache_query_indirect(session->decoder, override_ip);
    if (result < 0) {
        return result;
    }

    *override_ip -= session->binary_slide;

#if HA_ENABLE_ANALYSIS_LOGS
    if (result == 1) {
        printf(TAG "\tasync event update, switching to %p\n", (void *)*override_ip);
    } else {
        printf(TAG "\tvv indirect from to %p\n", (void *)*override_ip);
    }
#endif

    return 0;
}

int ha_session_take_conditional(ha_session_t session, uint64_t *override_ip) {
    int taken = ha_pt_decoder_cache_query_tnt(session->decoder, override_ip);
    if (taken == 2) {
        //Override
        *override_ip -= session->binary_slide;

#if HA_ENABLE_ANALYSIS_LOGS
        printf(TAG "\tasync event update, switching to %p\n", (void *)*override_ip);
#endif

        return 0x3;
    }


#if HA_ENABLE_ANALYSIS_LOGS
    printf(TAG "\tvv taking conditional: %d\n", taken);
    if (taken != 0 && taken != 1) {
        abort();
    }
#endif

    return taken;
}

//MARK: - Simple custom trace implementations

int ha_session_generate_coverage(ha_session_t session) {
    //FIXME: Not implemented
    abort();
}

//int c = 0;
static void print_trace(ha_session_t session, uint64_t unslid_ip) {
#if HA_ENABLE_BLOCK_LEVEL_LOGS
    printf("%p\n", (void *)unslid_ip);
#endif
//    if (c == 5) {
//        printf("STOP!\n");
//    }
//    c++;
}

int ha_session_print_trace(ha_session_t session) {
    session->on_block_function = print_trace;
#if HA_ENABLE_BLOCK_LOGS
    printf(TAG "--BEGIN TRACE DECODE--\n");
#endif
    return ha_mirror_block_decode(session);
}
