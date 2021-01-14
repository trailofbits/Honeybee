//
// Created by Allison Husain on 1/12/21.
//

#ifndef HA_CAPTURE_SESSION_H
#define HA_CAPTURE_SESSION_H

#include <stdint.h>

typedef struct ha_capture_session_internal *ha_capture_session_t;

/**
 * Represents a single range filter
 */
typedef struct {
    /**
     * If this filter should be enabled. If this value is zero, start and stop are ignored
     */
    unsigned char enabled;

    /**
     * The start (inclusive) virtual address for the filter.
     * Code between [start, stop) will be sent to the trace buffer. Everything else (that is not matching any other
     * filter) will be IGNORED.
     */
    uint64_t start;

    /**
     * The end (exclusive) virtual address for the filter
     */
    uint64_t stop;
} ha_capture_session_range_filter;

/**
 * Create a new capture session for the Honeybee driver
 * @param session_out The location to place the session if successful
 * @param cpu_id The CPU ID (zero indexed) that this session should manage and capture PT data on. Nothing is stopping
 * you from launching multiple sessions on the same CPU, it's just a really bad idea.
 * @return A status code. Negative on error.
 */
int ha_capture_session_alloc(ha_capture_session_t *session_out, uint16_t cpu_id);

/**
 * Frees a capture session and tears down any trace buffers.
 */
void ha_capture_session_free(ha_capture_session_t session);

/**
 * Set the global buffer size to be used for all CPUs. This is only allowed when no CPUs are tracing. This triggers
 * an immediate release of any existing buffers.
 * @param buffer_count The number of buffers to allocate per CPU
 * @param page_power This indirectly controls the buffer size by the formula (PAGE_SIZE << page_power)
 * @return A status code. Negative on error.
 */
int ha_capture_session_set_global_buffer_size(ha_capture_session_t session, uint32_t buffer_count, uint8_t page_power);

/**
 * Starts or stops tracing on this session's CPU
 * @param enabled Non-zero if tracing should be enabled
 * @param If the trace buffer output should be reset to the start. If false and the trace has not been reconfigured
 * since being disabled, tracing will resume without damaging data.
 * @return A status code. Negative on error.
 */
int ha_capture_session_set_trace_enable(ha_capture_session_t session, uint8_t enabled, uint8_t reset_output);

/**
 * Configures tracing on the CPU. This is only valid when the CPU is not tracing.
 * @param pid The PID to trace. This process should be bound to this session's CPU (sched_setaffinity) otherwise the
 * trace data will not accurately reflect what the process did.
 * @param filters The filters to apply. Note, not all of these filters will be applied. The kernel applies the first
 * n filters, where n is the number of filters this hardware supports. Put the filters you want to apply most first :)
 * @return A status code. Negative on error.
 */
int ha_capture_session_configure_tracing(ha_capture_session_t session, uint32_t pid,
                                         ha_capture_session_range_filter filters[4]);

/**
 * Gets the trace buffer. This trace buffer has a stop codon (PT_TRACE_END) at the end of it.
 * Note: you do not own this buffer and it will be destroyed when this session is freed or a new trace is launched on
 * this core.
 * @param trace_buffer The location to place a pointer to the trace buffer. Nothing is written on error.
 * @param trace_length The location to place the length of the trace and the stop codon. Nothing is written on error.
 * @return A status code. Negative on error.
 */
int ha_capture_get_trace(ha_capture_session_t session, uint8_t **trace_buffer, uint64_t *trace_length);

#endif //HA_CAPTURE_SESSION_H
