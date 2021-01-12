//
// Created by Allison Husain on 12/23/20.
//
#include <stdlib.h>
#include <stdio.h>

#include "ha_session.h"
#include "ha_session_internal.h"
#include "../ha_debug_switch.h"

#define TAG "[" __FILE__ "] "

/**
 * Get the lower 32 bytes
 */
#define LO32(x) ((uint32_t)(x))

int ha_session_alloc(ha_session_t *session_out, const char *hive_path) {
    int result = 0;

    if (!(session_out && hive_path)) {
        //Invalid argument
        result = -1;
        goto CLEANUP;
    }

    ha_session *session = calloc(1, sizeof(ha_session));
    if (!session) {
        result = -2;
        goto CLEANUP;
    }

    if (!(session->hive = hb_hive_alloc(hive_path))) {
        result = -3;
        goto CLEANUP;
    }

    session->decoder = ha_pt_decoder_alloc();
    if (!session->decoder) {
        result = -3;
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

int ha_session_reconfigure_with_rw_trace_buffer(ha_session_t session, uint8_t *trace_buffer, uint64_t trace_length,
                                                uint64_t trace_slide) {
    if (!(session && trace_buffer)) {
        return -1;
    }

    session->trace_slide = trace_slide;
    ha_pt_decoder_reconfigure_with_trace(session->decoder, trace_buffer, trace_length);

    return ha_pt_decoder_sync_forward(session->decoder);
}


void ha_session_free(ha_session_t session) {
    if (!session) {
        return;
    }

    if (session->decoder) {
        ha_pt_decoder_free(session->decoder);
        session->decoder = NULL;
    }

    if (session->hive) {
        hb_hive_free(session->hive);
        session->hive = NULL;
    }

    free(session);
}

/**
 * Initiates a block level trace decode using the session's on_block_function and extra_context
 * @param session
 * @return A negative code on error. An end-of-stream error is the expected exit code.
 */
__attribute__ ((hot))
int64_t block_decode(ha_session_t session) {
    uint64_t index;
    uint64_t vip;
    uint64_t *blocks = session->hive->blocks;
    int64_t status;
#if HA_BLOCK_REPORTS_ARE_EDGE_TRANSITIONS
    uint64_t last_report = 0;
#endif

    //We need to take an indirect jump since we currently don't have a starting state
    goto TRACE_INIT;
    while (status >= 0) {
#if HA_BLOCK_REPORTS_ARE_EDGE_TRANSITIONS
        //This is the AFL edge transition function
        uint64_t report = (last_report << 1) ^ LO32(index);
        session->on_block_function(session, session->extra_context, report);
        last_report = LO32(index);
#else
        session->on_block_function(session, session->extra_context, LO32(vip) + session->hive->uvip_slide);
#endif

        if (LO32(index) >= session->hive->block_count) {
            return -HA_PT_DECODER_INTERNAL;
        }

        /* if we inline both take_conditional and take_indirect and have them both pre-fetched, we can do a branchless increment on the value we consume */
        vip = blocks[2 * LO32(index) + 1];
        index = blocks[2 * LO32(index)];

        if (index & HB_HIVE_FLAG_IS_CONDITIONAL) {
            uint64_t result = ha_pt_decoder_cache_query_tnt(session->decoder, &vip);
            if (result == 2 /* override */) {
#if HA_ENABLE_ANALYSIS_LOGS
                printf("\tTNT result = 2: override destination to %p\n", (void *) vip);
#endif
                vip -= session->trace_slide;
                index = hb_hive_virtual_address_to_block_index(session->hive, vip);
            } else if (result == 1 /* taken */) {
                index >>= 1;
#if HA_ENABLE_ANALYSIS_LOGS
                printf("\tTNT result = 1: vip = %p\n", (void *)(uint64_t)(LO32(vip)) + session->hive->uvip_slide);
#endif
            } else if (result == 0 /* not taken */) {
                index >>= 33;
                vip >>= 32;

#if HA_ENABLE_ANALYSIS_LOGS
                printf("\tTNT result = 0: vip = %p\n", (void *)(uint64_t)(LO32(vip)) + session->hive->uvip_slide);
#endif
            }
        } else {
            /* taken or direct -- cuts off the conditional flag or the zero bit if NT */
            index >>= 1;
        }

        if (LO32(index) == HB_HIVE_FLAG_INDIRECT_JUMP_INDEX_VALUE) {
            TRACE_INIT:
            status = ha_pt_decoder_cache_query_indirect(session->decoder, &vip);
            vip -= session->trace_slide;
            index = hb_hive_virtual_address_to_block_index(session->hive, vip);
            vip -= session->hive->uvip_slide;

#if HA_ENABLE_ANALYSIS_LOGS
            printf("\tIndirect: vip = %p\n", (void *) (uint64_t) (LO32(vip)));
#endif
        }
    }

    return status;
}
//static int64_t block_decode(ha_session_t session) {
//    uint64_t index;
//    uint64_t vip;
//    uint64_t *blocks = session->hive->blocks;
//    int64_t status;
//
//    //We need to take an indirect jump since we currently don't have a starting state
//    goto TRACE_INIT;
//    while (status >= 0) {
//        session->on_block_function(session, session->extra_context, LO32(vip) + session->hive->uvip_slide);
//
//        if (LO32(index) >= session->hive->block_count) {
//            return -HA_PT_DECODER_INTERNAL;
//        }
//
//        /* if we inline both take_conditional and take_indirect and have them both pre-fetched, we can do a branchless increment on the value we consume */
//        vip = blocks[2 * LO32(index) + 1];
//        index = blocks[2 * LO32(index)];
//
//        if (index & HB_HIVE_FLAG_IS_CONDITIONAL) {
//            uint64_t result = ha_pt_decoder_cache_query_tnt(session->decoder, &vip);
//            if (result == 2 /* override */) {
//#if HA_ENABLE_ANALYSIS_LOGS
//                printf("\tTNT result = 2: override destination to %p\n", (void *)vip);
//#endif
//                vip -= session->trace_slide;
//                index = hb_hive_virtual_address_to_block_index(session->hive, vip);
//            } else if (result == 1 /* taken */) {
//                index >>= 1;
//#if HA_ENABLE_ANALYSIS_LOGS
//                printf("\tTNT result = 1: vip = %p\n", (void *)(uint64_t)(LO32(vip)) + session->hive->uvip_slide);
//#endif
//            } else if (result == 0 /* not taken */) {
//                index >>= 33;
//                vip >>= 32;
//
//#if HA_ENABLE_ANALYSIS_LOGS
//                printf("\tTNT result = 0: vip = %p\n", (void *)(uint64_t)(LO32(vip)) + session->hive->uvip_slide);
//#endif
//            }
//        } else {
//            /* taken or direct -- cuts off the conditional flag or the zero bit if NT */
//            index >>= 1;
//        }
//
//        if (LO32(index) == HB_HIVE_FLAG_INDIRECT_JUMP_INDEX_VALUE) {
//            TRACE_INIT:
//            status = ha_pt_decoder_cache_query_indirect(session->decoder, &vip);
//            vip -= session->trace_slide;
//            index = hb_hive_virtual_address_to_block_index(session->hive, vip);
//            vip -= session->hive->uvip_slide;
//
//#if HA_ENABLE_ANALYSIS_LOGS
//            printf("\tIndirect: vip = %p\n", (void *)(uint64_t)(LO32(vip)));
//#endif
//        }
//    }
//
//    return status;
//}


int ha_session_decode(ha_session_t session, ha_hive_on_block_function *on_block_function, void *context) {
    session->on_block_function = on_block_function;
    session->extra_context = context;

    return block_decode(session);
}

//int c = 0;
static void print_trace(ha_session_t session, void *context, uint64_t unslid_ip) {
#if HA_ENABLE_BLOCK_LEVEL_LOGS
    printf("%p\n", (void *) unslid_ip);
#endif
//    if (c == 5) {
//        printf("STOP!\n");
//    }
//    c++;
}

int ha_session_print_trace(ha_session_t session) {
#if HA_ENABLE_BLOCK_LOGS
    printf(TAG "--BEGIN TRACE DECODE--\n");
#endif
    return ha_session_decode(session, print_trace, NULL);
}
