//
// Created by Allison Husain on 12/23/20.
//

#include <stdio.h>
#include <limits.h>

#include "intel-pt.h"

#include "ha_session.h"
#include "ha_mirror_utils.h"



typedef struct internal_ha_session {
    /**
     * The function called by this session when a block is decoded
     * NOTE: DO NOT MOVE THIS WITHOUT UPDATING ha_block_decode_thunks !!!
     */
    ha_mirror_on_block_function *on_block_function;

    /**
     * The session's decoder
     */
    struct pt_query_decoder *decoder;

    /**
     * The (for now) global slide. This will be subtracted from all trace addresses to get the un-slid value
     */
    uint64_t binary_slide;

    /**
     * The slid virtual IP that this session is seeding itself with
     * This is found by advancing the decoder just enough to get an initial IP
     */
    uint64_t initial_unslid_ip;
} ha_session;

/**
 * Parses any waiting events. If a new IP is detected in the event stream, the latest un-slid IP will be returned.
 * @param status The last status result (such as from querying for a conditional branch)
 * @param override_ip The location to place the un-slid IP if a new one is found. If no new IP is found, nothing is
 * written to this address.
 * @return A new libipt status
 */
static int handle_events(ha_session *session, int status, uint64_t *override_ip) {
    while (status & pts_event_pending) {
        struct pt_event event;

        status = pt_qry_event(session->decoder, &event, sizeof(event));
        if (status < 0)
            break;

        printf("event!: %d\n", event.type);
        if (event.type == ptev_enabled) {
            *override_ip = event.variant.enabled.ip - session->binary_slide;
            printf("\tenable: %p\n", (void *)(*override_ip));
        }
    }

    return status;
}


int ha_session_alloc(ha_session_t *session_out, const uint8_t *pt_buffer, size_t pt_buffer_len, uint64_t binary_slide) {
    int result = 0;

    if (!(session_out && pt_buffer && pt_buffer_len)) {
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

    /* libipt configuration */

    struct pt_config config;
    bzero(&config, sizeof(struct pt_config));
    config.size = sizeof(struct pt_config);
    config.begin = (uint8_t *)(pt_buffer);
    config.end = (uint8_t *)(pt_buffer + pt_buffer_len);

    session->decoder = pt_qry_alloc_decoder(&config);
    if (!session->decoder) {
        result = -3;
        goto CLEANUP;
    }

    /* POST INIT -- all structure objects MUST be created before this point */

    result = pt_qry_sync_forward(session->decoder, &session->initial_unslid_ip);
    if (result < 0) {
        goto CLEANUP;
    }

    result = handle_events(session, result, &session->initial_unslid_ip);
    if (result < 0) {
        goto CLEANUP;
    }

    if (!session->initial_unslid_ip) {
        result = -4;
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
        pt_qry_free_decoder(session->decoder);
        session->decoder = NULL;
    }

    free(session);
}

int ha_session_generate_coverage(ha_session_t session) {
    //FIXME: Not implemented
    abort();
}

int ha_session_perform_libipt_audit(ha_session_t session, const char *binary_path) {
    //FIXME: Not implemented
    abort();
}

static void print_trace(ha_session_t session, uint64_t unslid_ip) {
    printf("logger: %p\n", (void *)unslid_ip);
}

int ha_session_print_trace(ha_session_t session) {
    session->on_block_function = print_trace;
    printf("START TRACE\n");
    return ha_mirror_block_decode(session, session->initial_unslid_ip);
}

int ha_session_take_indirect_branch(ha_session_t session, uint64_t *override_ip, uint64_t *override_code_location) {
    int status;
    if ((status = pt_qry_indirect_branch(session->decoder, override_ip)) < 0) {
        return status;
    }
    *override_ip -= session->binary_slide;

    /* handle events returns a slid IP */
    if ((status = handle_events(session, status, override_ip))) {
        return status;
    }


    *override_code_location = ha_mirror_utils_convert_unslid_to_code(*override_ip);
    if (!*override_code_location) {
        return -1;
    }

    printf("\tvv indirect from to %p\n", (void *)*override_ip);

    return 0;
}

int ha_session_take_conditional(ha_session_t session, uint64_t *override_ip, uint64_t *override_code_location) {
    int status;
    int taken = -1;
    uint64_t updated_ip = 0;

    if ((status = pt_qry_cond_branch(session->decoder, &taken)) < 0
        || (status = handle_events(session, status, &updated_ip)) < 0) {
        return status;
    }

    printf("\tvv taking conditional: %d\n", taken);

    if (updated_ip) {
        //We got a new IP from the trace. We need to submit a new IP and __TEXT location to continue decoding at.
        *override_ip = updated_ip;
        *override_code_location = ha_mirror_utils_convert_unslid_to_code(updated_ip);
        printf("\tevent update, switching to %p\n", (void *)updated_ip);
        return 0x3;
    } else if (status < 0) {
        return status;
    }

    return taken;
}