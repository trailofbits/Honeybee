//
// Created by Allison Husain on 12/30/20.
//

#ifndef HONEY_ANALYZER_HA_SESSION_INTERNAL_H
#define HONEY_ANALYZER_HA_SESSION_INTERNAL_H

#include "../processor_trace/ha_pt_decoder.h"
#include "../../honeybee_shared/hb_hive.h"

/**
 * This is the internal representation of an ha_session. This is exposed in a separate header for custom loggers. If
 * you are consuming an ha_session_t you should not use this.
 */
typedef struct internal_ha_session {
    /**
     * The session's decoder
     */
    ha_pt_decoder_t decoder;

    /**
     * The hive to use for decoding traces
     */
    hb_hive *hive;

    /**
     * The (for now) global slide. This is the base address of the traced binary during the current trace
     */
    uint64_t trace_slide;

    /**
     * The function called by this session when a block is decoded
    */
    ha_hive_on_block_function *on_block_function;

    /**
     * An addition field which custom decoders can use
     */
    void *extra_context;
} ha_session;

#endif //HONEY_ANALYZER_HA_SESSION_INTERNAL_H
