//
// Created by Allison Husain on 12/30/20.
//

#ifndef HONEY_ANALYZER_HA_SESSION_AUDIT_H
#define HONEY_ANALYZER_HA_SESSION_AUDIT_H

#include "../../honey_analyzer/trace_analysis/ha_session.h"

enum ha_session_audit_status {
    /** The audit passed. libipt and Honeybee produced essentially identical outputs. */
    HA_SESSION_AUDIT_TEST_PASS = 0,
    /** The test could not be started */
    HA_SESSION_AUDIT_TEST_INIT_FAILED = 1,
    /**libipt gave an error while decoding the trace */
    HA_SESSION_AUDIT_TEST_LIBIPT_ERROR = 2,
    /** Honeybee gave an error while decoding the trace */
    HA_SESSION_AUDIT_TEST_HONEYBEE_ERROR = 3,
    /** Honeybee and libipt disagree on how a trace should be decoded */
    HA_SESSION_AUDIT_TEST_INCORRECT_RESULT = 4,
};

/**
 * Decode the trace using both the mirror and using libipt's block decoder and compare results.
 * This is useful for testing the correctness of mirrors.
 * @param binary_path The path to the binary used to create the mirror/this trace. This is used by libipt.
 * @return 0 on success, negative on error. Error codes come from enum ha_session_audit_status.
 */
int ha_session_audit_perform_libipt_audit(ha_session_t session, const char *binary_path,
                                          uint8_t *trace_buffer, uint64_t trace_length);

#endif //HONEY_ANALYZER_HA_SESSION_AUDIT_H
