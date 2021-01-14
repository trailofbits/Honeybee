//
// Created by Allison Husain on 1/12/21.
//

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "ha_capture_session.h"
#include "../../honeybee_shared/hb_driver_packets.h"
#include "../processor_trace/ha_pt_decoder_constants.h"

struct ha_capture_session_internal {
    /**
     * The CPU we're configure to trace on
     */
    uint16_t cpu_id;

    /**
     * The device driver handle
     */
    int fd;

    /**
     * The handle for the trace buffer. Note, we vend this to external users, though they do not own it.
     */
    uint8_t *mmap_handle;

    /**
     * The size of our mmap'd region
     */
    uint64_t mmap_size;
};

int ha_capture_session_alloc(ha_capture_session_t *session_out, uint16_t cpu_id) {
    ha_capture_session_t session = calloc(1, sizeof(struct ha_capture_session_internal));
    if (!session) {
        return -ENOMEM;
    }

    session->cpu_id = cpu_id;
    session->fd = open("/dev/honey_driver", O_CLOEXEC | O_RDWR);
    if (session->fd < 0) {
        ha_capture_session_free(session);
        return -errno;
    }

    *session_out = session;

    return 0;
}

void ha_capture_session_free(ha_capture_session_t session) {
    if (!session) {
        return;
    }

    if (session->fd >= 0) {
        close(session->fd);
    }

    if (session->mmap_handle && session->mmap_handle != MAP_FAILED) {
        munmap(session->mmap_handle, session->mmap_size);
    }

    free(session);
}

int ha_capture_session_set_global_buffer_size(ha_capture_session_t session, uint32_t buffer_count, uint8_t page_power) {
    //If we're changing the buffer size, we need to invalidate our mapping
    if (session->mmap_handle && session->mmap_handle != MAP_FAILED) {
        munmap(session->mmap_handle, session->mmap_size);
        session->mmap_handle = NULL;
        session->mmap_size = 0;
    }

    hb_driver_packet_configure_buffers configure_buffers;
//    bzero(&configure_buffers, sizeof configure_buffers);

    configure_buffers.count = buffer_count;
    configure_buffers.page_count_power = page_power;

    return ioctl(session->fd, HB_DRIVER_PACKET_IOC_CONFIGURE_BUFFERS, &configure_buffers);
}


int ha_capture_session_set_trace_enable(ha_capture_session_t session, uint8_t enabled, uint8_t reset_output) {
    hb_driver_packet_set_enabled set_enabled;
//    bzero(&set_enabled, sizeof set_enabled);

    set_enabled.cpu_id = session->cpu_id;
    set_enabled.enabled = enabled ? 1 : 0;
    set_enabled.reset_output = reset_output;

    return ioctl(session->fd, HB_DRIVER_PACKET_IOC_SET_ENABLED, &set_enabled);
}

int ha_capture_session_configure_tracing(ha_capture_session_t session, uint32_t pid,
                                         ha_capture_session_range_filter filters[4]) {
    hb_driver_packet_configure_trace configure_trace;
//    bzero(&configure_trace, sizeof configure_trace);

    configure_trace.cpu_id = session->cpu_id;
    configure_trace.pid = pid;

    for (int i = 0; i < 4; i++) {
        hb_driver_packet_range_filter *dst_filter = &configure_trace.filters[i];
        ha_capture_session_range_filter *src_filter = &filters[i];
        dst_filter->enabled = src_filter->enabled;
        dst_filter->start_address = src_filter->start;
        dst_filter->stop_address = src_filter->stop;
    }

    return ioctl(session->fd, HB_DRIVER_PACKET_IOC_CONFIGURE_TRACE, &configure_trace);
}

static int get_trace_buffer_lengths(ha_capture_session_t session, uint64_t *packet_byte_count, uint64_t *buffer_size) {
    hb_driver_packet_get_trace_lengths get_trace_lengths;
//    bzero(&get_trace_lengths, sizeof get_trace_lengths);

    get_trace_lengths.cpu_id = session->cpu_id;
    get_trace_lengths.trace_packet_byte_count_out = packet_byte_count;
    get_trace_lengths.trace_buffer_length_out = buffer_size;

    return ioctl(session->fd, HB_DRIVER_PACKET_IOC_GET_TRACE_LENGTHS, &get_trace_lengths);
}

int ha_capture_get_trace(ha_capture_session_t session, uint8_t **trace_buffer, uint64_t *trace_length) {
    int result;

    uint64_t packet_byte_count;
    uint64_t buffer_length;
    if ((result = get_trace_buffer_lengths(session, &packet_byte_count, &buffer_length)) < 0) {
        return result;
    }

    //We can abuse the fact that we re-use buffers by reusing the buffer
    if (!session->mmap_handle || session->mmap_handle == MAP_FAILED) {
        session->mmap_handle = mmap(NULL, buffer_length, PROT_READ | PROT_WRITE, MAP_SHARED, session->fd,
                /* offsets are passed in PAGE_SIZE multiples as non-aligned offsets are invalid */
                                    getpagesize() * session->cpu_id);

        if (session->mmap_handle == NULL || session->mmap_handle == MAP_FAILED) {
            return errno;
        }
        session->mmap_size = buffer_length;
    }

    /* Terminate the buffer using our stop codon */
    if (packet_byte_count >= buffer_length) {
        //We need to truncate the trace buffer to insert the stop codon
        //This isn't great, but this should really just not happen
        packet_byte_count = buffer_length - 1;
    }

    session->mmap_handle[packet_byte_count] = PT_TRACE_END;

    *trace_buffer = session->mmap_handle;
    *trace_length = packet_byte_count;

    return result;
}