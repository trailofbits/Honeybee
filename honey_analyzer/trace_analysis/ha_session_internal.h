//
// Created by Allison Husain on 12/30/20.
//

#ifndef HONEY_ANALYZER_HA_SESSION_INTERNAL_H
#define HONEY_ANALYZER_HA_SESSION_INTERNAL_H

#include "ha_mirror_utils.h"
#include "../processor_trace/ha_pt_decoder.h"

/**
 * This is the internal representation of an ha_session. This is exposed in a separate header for custom loggers. If
 * you are consuming an ha_session_t you should not use this.
 */
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

#endif //HONEY_ANALYZER_HA_SESSION_INTERNAL_H
