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
 * @param trace_path The path to the raw PT trace
 * @param binary_slide The ASLR slide of the binary
 * @return Error code. On success, zero is returned
 */
int ha_session_alloc(ha_session_t *session_out, const char *trace_path, uint64_t binary_slide);

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
 * Decode the trace using both the mirror and using libipt's block decoder and compare results.
 * This is useful for testing the correctness of mirrors.
 * @param binary_path The path to the binary used to create the mirror/this trace. This is used by libipt.
 * @return Non-zero if the mirror and libipt return different blocks
 */
int ha_session_perform_libipt_audit(ha_session_t session, const char *binary_path);

/**
 * Debug function. Walks the trace and dumps to the console.
 * @return Error code. On success, zero is returned
 */
int ha_session_print_trace(ha_session_t session);

/* functions meant for ha_mirrors */

/**
 * Queries the session for the destination of the next indirect branch
 * @param session The session from which this request originates
 * @param override_ip The location to place the new un-slid virtual IP. NOTE: this may be a completely different
 * location if an event was processed which changed the IP.
 * @param override_code_location  The location to place the new __TEXT location for the next decoder block
 * @return A libipt error code. On error, override_ip and override_code_location are undefined
 */
int ha_session_take_indirect_branch(ha_session_t session, uint64_t *override_ip, uint64_t *override_code_location)
    asm("_ha_session_take_indirect_branch");

/**
 * Queries the session for the direction of the next conditional branch
 * @param session The session from which this request originates
 * @param override_ip The location to place the new virtual IP if an event was processed which redirects execution.
 * If no event changes the IP, this value is left unchanged.
 * @param override_code_location  The location to place the new __TEXT location for the next decoder block if an event
 * was processed which redirects execution. If no event changes the IP, this value is left unchanged.
 * @return A negative value indicates a libipt error. A value of 0 indicates the branch was not taken. A value of 1
 * indicates that the branch was taken. A value of 0x3 indicates an override update.
 */
int ha_session_take_conditional(ha_session_t session, uint64_t *override_ip, uint64_t *override_code_location)
    asm("_ha_session_take_conditional");


#endif //HONEY_ANALYSIS_HA_SESSION_H
