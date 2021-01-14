//
// Created by Allison Husain on 12/23/20.
//

#ifndef HONEY_ANALYSIS_HA_SESSION_H
#define HONEY_ANALYSIS_HA_SESSION_H

#include <stdlib.h>
#include <stdint.h>
#include "../../honeybee_shared/hb_hive.h"

typedef struct internal_ha_session *ha_session_t;

/**
 * A function which the block decoder will call whenever it encounters a block
 */
typedef void (ha_hive_on_block_function)(ha_session_t session, void *context, uint64_t unslid_ip);

/**
 * Create a new trace session from a trace file
 * @param session_out The location to place a pointer to the created session. On error, left unchanged.
 * @param hive The Honeybee hive to use for decoding this trace.
 * @return Error code. On success, zero is returned
 */
int ha_session_alloc(ha_session_t *session_out, hb_hive *hive);


/**
 * (Re)configures the session with a new trace. This is a zero allocation operation.
 * @param trace_buffer The pointer to the start of the buffer containing the trace data. NOTE: This pointer is NOT
 * owned by the session, you are responsible for destroying it.
 * @param trace_length The length of the trace (read: NOT THE BUFFER ITSELF). The actual length of the buffer must be
 * @param trace_slide The base address of the binary for this trace in memory
 * @return Error code. On success, zero is returned
 */
int ha_session_reconfigure_with_terminated_trace_buffer(ha_session_t session, uint8_t *trace_buffer,
                                                        uint64_t trace_length, uint64_t trace_slide);

/**
 * Frees a session and all of its owned components
 * @param session
 */
void ha_session_free(ha_session_t session);

/**
 * Decodes a trace and calls a function on each block.
 * @param on_block_function A callback function which will be invoked for each block
 * @param context An arbitrary pointer which will be passed to the on_block_function
 * @return A negative code on error. An end-of-stream error is the expected exit code.
 */
int ha_session_decode(ha_session_t, ha_hive_on_block_function *on_block_function, void *context);

/**
 * Debug function. Walks the trace and dumps to the console.
 * @return A negative code on error. An end-of-stream error is the expected exit code.
 */
int ha_session_print_trace(ha_session_t session);


#endif //HONEY_ANALYSIS_HA_SESSION_H
