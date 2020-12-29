//
// Created by Allison Husain on 12/23/20.
//
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "intel-pt.h"

#include "ha_session.h"
#include "ha_mirror_utils.h"

#define TAG "[" __FILE__ "] "

#define DEBUG_LOGGING 0
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

    /**
     * The last libipt query decoder status. This is used to lob async events forwards so that they're taken one at a
     * time.
     */
    int last_decode_status;

    /**
     * An addition field which custom decoders can use
     */
    void *extra_context;
} ha_session;

/* forward declarations */
static int handle_events(ha_session *session, int status, uint64_t *override_ip);

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

    if (result & pts_ip_suppressed) {
        result = handle_events(session, result, &session->initial_unslid_ip);
        if (result < 0) {
            goto CLEANUP;
        }
    }

    //init our decode status with our last decode result
    session->last_decode_status = result;

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
#include <inttypes.h>
static void print_event(const struct pt_event *event) {
    printf(TAG "[");
    switch (event->type) {
        case ptev_enabled:
            printf("%s", event->variant.enabled.resumed ? "resumed" :
                         "enabled");
            printf(", ip: %016" PRIx64, event->variant.enabled.ip);
            break;

        case ptev_disabled:
            printf("disabled");
                printf(", ip: %016" PRIx64, event->variant.disabled.ip);
            break;

        case ptev_async_disabled:
            printf("disabled");
                printf(", at: %016" PRIx64,
                        event->variant.async_disabled.at);

                if (!event->ip_suppressed)
                    printf(", ip: %016" PRIx64,
                        event->variant.async_disabled.ip);
            break;

        case ptev_async_branch:
            printf("interrupt");
                printf(", from: %016" PRIx64,
                        event->variant.async_branch.from);

                if (!event->ip_suppressed)
                    printf(", to: %016" PRIx64,
                        event->variant.async_branch.to);
            break;

        case ptev_paging:
            printf("paging, cr3: %016" PRIx64 "%s",
            event->variant.paging.cr3,
            event->variant.paging.non_root ? ", nr" : "");
            break;

        case ptev_async_paging:
            printf("paging, cr3: %016" PRIx64 "%s",
            event->variant.async_paging.cr3,
            event->variant.async_paging.non_root ? ", nr" : "");
                printf(", ip: %016" PRIx64,
            event->variant.async_paging.ip);
            break;

        case ptev_overflow:
            printf("overflow");

                printf(", ip: %016" PRIx64, event->variant.overflow.ip);
            break;

        case ptev_exec_mode:
            printf("exec mode: %d", event->variant.exec_mode.mode);
                printf(", ip: %016" PRIx64,
            event->variant.exec_mode.ip);
            break;

        case ptev_tsx:
            if (event->variant.tsx.aborted)
                printf("aborted");
            else if (event->variant.tsx.speculative)
                printf("begin transaction");
            else
                printf("committed");

                printf(", ip: %016" PRIx64, event->variant.tsx.ip);
            break;

        case ptev_stop:
            printf("stopped");
            break;

        case ptev_vmcs:
            printf("vmcs, base: %016" PRIx64, event->variant.vmcs.base);
            break;

        case ptev_async_vmcs:
            printf("vmcs, base: %016" PRIx64,
            event->variant.async_vmcs.base);

                printf(", ip: %016" PRIx64,
            event->variant.async_vmcs.ip);
            break;

        case ptev_exstop:
            printf("exstop");

                printf(", ip: %016" PRIx64, event->variant.exstop.ip);
            break;

        case ptev_mwait:
            printf("mwait %" PRIx32 " %" PRIx32,
            event->variant.mwait.hints, event->variant.mwait.ext);

                printf(", ip: %016" PRIx64, event->variant.mwait.ip);
            break;

        case ptev_pwre:
            printf("pwre c%u.%u", (event->variant.pwre.state + 1) & 0xf,
                   (event->variant.pwre.sub_state + 1) & 0xf);

            if (event->variant.pwre.hw)
                printf(" hw");
            break;


        case ptev_pwrx:
            printf("pwrx ");

            if (event->variant.pwrx.interrupt)
                printf("int: ");

            if (event->variant.pwrx.store)
                printf("st: ");

            if (event->variant.pwrx.autonomous)
                printf("hw: ");

            printf("c%u (c%u)", (event->variant.pwrx.last + 1) & 0xf,
                   (event->variant.pwrx.deepest + 1) & 0xf);
            break;

        case ptev_ptwrite:
            printf("ptwrite: %" PRIx64, event->variant.ptwrite.payload);

                printf(", ip: %016" PRIx64, event->variant.ptwrite.ip);
            break;

        case ptev_tick:
            printf("tick");

                printf(", ip: %016" PRIx64, event->variant.tick.ip);
            break;

        case ptev_cbr:
            printf("cbr: %x", event->variant.cbr.ratio);
            break;

        case ptev_mnt:
            printf("mnt: %" PRIx64, event->variant.mnt.payload);
            break;
        default:
            printf("[[unknown event]]\n");
    }

    printf("]\n");
}


/**
 * Parses any waiting events. If a new IP is detected in the event stream, the latest un-slid IP will be returned.
 * @param status The last status result (such as from querying for a conditional branch)
 * @param override_ip The location to place the un-slid IP if a new one is found. If no new IP is found, nothing is
 * written to this address.
 * @return A new libipt status
 */
static int handle_events(ha_session *session, int status, uint64_t *override_ip) {
    uint64_t disabled_ip_slid = 0;
    while (status & pts_event_pending) {
        struct pt_event event;

        status = pt_qry_event(session->decoder, &event, sizeof(event));
        if (status < 0)
            break;

#if DEBUG_LOGGING
        print_event(&event);
#endif

        switch (event.type) {
            case ptev_disabled:
                disabled_ip_slid = event.variant.disabled.ip;
                break;
            case ptev_async_disabled:
                disabled_ip_slid = event.variant.async_disabled.at;
                break;
            case ptev_tsx:
                if (event.variant.tsx.ip) {
                    *override_ip = event.variant.enabled.ip - session->binary_slide;
                    return status | FLAG_DID_OVERRIDE_IP;
                }

                break;
            case ptev_enabled:
                if (event.variant.enabled.ip != disabled_ip_slid /* block resume IPs */) {
                    *override_ip = event.variant.enabled.ip - session->binary_slide;
                    uint64_t off;
                    pt_blk_get_offset(session->extra_context, &off);
                    if (off == 6844) {
                        printf("A");
                    }
                    return status | FLAG_DID_OVERRIDE_IP;
                }
                break;
            default:
                break;
        }
    }

    return status;
}

int ha_session_take_indirect_branch(ha_session_t session, uint64_t *override_ip, uint64_t *override_code_location) {
    if (session->last_decode_status & pts_event_pending) {
        //We have events pending from last time. Process them before continuing. If we get a flow update, do not query
        session->last_decode_status = handle_events(session, session->last_decode_status, override_ip);
        if (session->last_decode_status & FLAG_DID_OVERRIDE_IP) {
            //We had an IP update. Override!!!
            *override_code_location = ha_mirror_utils_convert_unslid_to_code(*override_ip);

            if (!*override_code_location) {
                return -1;
            }

#if DEBUG_LOGGING
            uint64_t off;
            pt_blk_get_offset(session->extra_context, &off);
            printf(TAG "\tasync event update, switching to %p @ %llu\n", (void *)*override_ip, off);
#endif

            return 0;
        }
    }

    if ((session->last_decode_status = pt_qry_indirect_branch(session->decoder, override_ip)) < 0) {
        return session->last_decode_status;
    }

    *override_ip -= session->binary_slide;
    *override_code_location = ha_mirror_utils_convert_unslid_to_code(*override_ip);
    if (!*override_code_location) {
        return -1;
    }

#if DEBUG_LOGGING
    printf(TAG "\tvv indirect from to %p\n", (void *)*override_ip);
#endif

    return 0;
}

int ha_session_take_conditional(ha_session_t session, uint64_t *override_ip, uint64_t *override_code_location) {
    int taken = -1;

    if (session->last_decode_status & pts_event_pending) {
        //We have events pending from last time. Process them before continuing. If we get a flow update, do not query
        session->last_decode_status = handle_events(session, session->last_decode_status, override_ip);
        if (session->last_decode_status & FLAG_DID_OVERRIDE_IP) {
            //We had an IP update. Override!!!
            *override_code_location = ha_mirror_utils_convert_unslid_to_code(*override_ip);

            if (!*override_code_location) {
                return -1;
            }

#if DEBUG_LOGGING
            uint64_t off;
            pt_blk_get_offset(session->extra_context, &off);
            printf(TAG "\tasync event update, switching to %p @ %llu\n", (void *)*override_ip, off);
#endif
            return 0x3;
        }
    }

    uint64_t updated_ip = 0;
    if ((session->last_decode_status = pt_qry_cond_branch(session->decoder, &taken)) < 0) {
        return session->last_decode_status;
    }

#if DEBUG_LOGGING
    printf(TAG "\tvv taking conditional: %d\n", taken);
#endif

    if (session->last_decode_status < 0) {
        return session->last_decode_status;
    }

    return taken;
}

//MARK: - Custom trace implementations

int ha_session_generate_coverage(ha_session_t session) {
    //FIXME: Not implemented
    abort();
}

static void libipt_audit_on_block(ha_session_t session, uint64_t mirror_unslid_ip) {
    struct pt_block_decoder *block_decoder = session->extra_context;
    int result = 0;
    struct pt_block block;
    bzero(&block, sizeof(struct pt_block));
    while (block.ninsn == 0) {
        result = pt_blk_next(block_decoder, &block, sizeof(block));
        while (result & pts_event_pending) {
            if (result < 0) {
                printf(TAG "Testing failed, libipt event decode error: %d\n", result);
                abort();
            }
            struct pt_event event;
            result = pt_blk_event(block_decoder, &event, sizeof(event));
        }

        if (result < 0) {
            printf(TAG "Testing failed, libipt block decode error: %d\n", result);
            abort();
        }
    }

    uint64_t libipt_unslid = block.ip - session->binary_slide;
    if (mirror_unslid_ip == libipt_unslid) {
        printf(TAG "PASS! mirror = %p, libipt = %p.\n", (void *)mirror_unslid_ip, (void *)libipt_unslid);
    } else {
        printf(TAG "*** AUDIT FAILED ***\n");
        printf(TAG "mirror = %p, libipt = %p. Aborting!\n", (void *)mirror_unslid_ip, (void *)libipt_unslid);
        abort();
    }
}

int ha_session_perform_libipt_audit(ha_session_t session, const char *binary_path) {
    int result = 0;
    int fd = 0;
    struct stat sb;
    struct pt_block_decoder *block_decoder = NULL;

    fd = open(binary_path, O_RDONLY);
    if (fd < 0) {
        printf(TAG "Failed to open binary!\n");
        result = fd;
        goto CLEANUP;
    }

    if ((result = fstat(fd, &sb)) < 0) {
        printf(TAG "Failed to fstat!\n");
        goto CLEANUP;
    }

    close(fd);
    fd = -1;

    /* libipt configuration */
    struct pt_config config;
    memcpy(&config, pt_qry_get_config(session->decoder), sizeof(struct pt_config));
    //Stop on all control flow in order to duplicate the behavior of mirrors
    config.flags.variant.block.end_on_jump = 1;
    config.flags.variant.block.end_on_call = 1;
    block_decoder = pt_blk_alloc_decoder(&config);

    if (!block_decoder) {
        result = 1;
        goto CLEANUP;
    }

    struct pt_image *image_unowned = pt_blk_get_image(block_decoder);

    if ((result = pt_image_add_file(image_unowned, binary_path, 0x00, sb.st_size, NULL, session->binary_slide)) < 0
        || (result = pt_blk_sync_forward(block_decoder)) < 0) {
        goto CLEANUP;
    }

    //Stash the block_decoder pointer so the logger function can access it
    session->extra_context = block_decoder;

    //Kickoff mirror decoding from our side
    session->on_block_function = libipt_audit_on_block;
    result = ha_mirror_block_decode(session, session->initial_unslid_ip);

    result = 0;

    CLEANUP:
    if (block_decoder) {
        pt_blk_free_decoder(block_decoder);
    }

    if (fd >= 0) {
        close(fd);
    }

    return result;
}

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
    return ha_mirror_block_decode(session, session->initial_unslid_ip);
}
