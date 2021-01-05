//
// Created by Allison Husain on 12/23/20.
//

#ifndef HONEY_ANALYSIS_HA_SESSION_H
#define HONEY_ANALYSIS_HA_SESSION_H
#include <stdlib.h>
#include <stdint.h>

typedef struct internal_ha_session * ha_session_t;

/**
 * Create a new trace session
 * @param session_out The location to place a pointer to the created session. On error, left unchanged.
 * @param hive_path The path to the Honeybee hive to use for decoding this trace.
 * @param trace_path The path to the raw PT trace
 * @param trace_slide The ASLR shifted base address of the binary for this trace
 * @return Error code. On success, zero is returned
 */
int ha_session_alloc(ha_session_t *session_out, const char *hive_path, const char *trace_path, uint64_t trace_slide);

/**
 * Frees a session and all of its owned components
 * @param session
 */
void ha_session_free(ha_session_t session);

/**
 * Generates the coverage map for the trace associated with this session
 * @return Error code. On success, zero is returned
 */
int ha_session_generate_coverage(ha_session_t session);

/**
 * Debug function. Walks the trace and dumps to the console.
 * @return Error code. On success, zero is returned
 */
int ha_session_print_trace(ha_session_t session);


#endif //HONEY_ANALYSIS_HA_SESSION_H
