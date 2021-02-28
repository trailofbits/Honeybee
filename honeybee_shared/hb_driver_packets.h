//
// Created by Allison Husain on 1/9/21.
//

#ifndef HONEY_DRIVER_HB_DRIVER_PACKETS_H
#define HONEY_DRIVER_HB_DRIVER_PACKETS_H

#ifndef __KERNEL__

#include <stdint.h>

#endif

#ifdef __APPLE__
#else
#include <linux/ioctl.h>
#endif

#define HB_DRIVER_PACKET_IOC_MAGIC 0xab

/**
 * (Re)allocates ToPA buffers on the CPU with a given size
 */
typedef struct {
    /**
     * The number of ToPA entries to allocate per CPU
     */
    uint32_t count;

    /**
     * The number of pages, as a power of 2, to allocate
     */
    uint8_t page_count_power;
} hb_driver_packet_configure_buffers;

#define HB_DRIVER_PACKET_IOC_CONFIGURE_BUFFERS _IOR(HB_DRIVER_PACKET_IOC_MAGIC, 1, hb_driver_packet_configure_buffers)

/**
 * A packet which configures the trace state of a single CPU
 */
typedef struct {
    /**
     * The ID of the CPU to control the state of
     */
    uint16_t cpu_id;

    /**
     * If non-zero, tracing is started on this CPU.
     * If zero, tracing is stopped, this terminates the trace buffer by placing a stop codon at the end of the trace.
     */
    uint8_t enabled;

    /**
     * If non-zero, the trace output will be reset.
     */
    uint8_t reset_output;
} hb_driver_packet_set_enabled;

#define HB_DRIVER_PACKET_IOC_SET_ENABLED _IOR(HB_DRIVER_PACKET_IOC_MAGIC, 2, hb_driver_packet_set_enabled)

/**
 * Describes a range trace filter
 */
typedef struct {
    /**
     * The starting address to include in the trace (inclusive)
     */
    uint64_t start_address;

    /**
     * The end of the range (exclusive)
     */
    uint64_t stop_address;

    /**
     * Zero if this filter is NOT used
     */
    uint8_t enabled;
} hb_driver_packet_range_filter;

#define HB_DRIVER_PACKET_CONFIGURE_TRACE_FILTER_COUNT 4
typedef struct {
    /**
     * The CPU this configuration should be applied to
     */
    uint16_t cpu_id;

    /**
     * The filters to apply. Note, only the first n filters will be applied (where n is the number of supported filters)
     */
    hb_driver_packet_range_filter filters[HB_DRIVER_PACKET_CONFIGURE_TRACE_FILTER_COUNT];

    /**
     * The PID to trace. This PID must be running (though it may be suspended).
     * This process should have its own memory space (i.e. already exec'd) since this PID is exchanged for a CR3
     * value internally.
     *
     * Note: this field is overwritten in the kernel copy of the structure with the UCR3 value
     */
    uint64_t pid;
} hb_driver_packet_configure_trace;

#define HB_DRIVER_PACKET_IOC_CONFIGURE_TRACE _IOR(HB_DRIVER_PACKET_IOC_MAGIC, 3, hb_driver_packet_configure_trace)

/**
 * Fetch the lengths of a trace buffer for a given CPU. This operation is only valid when the target is not tracing.
 */
typedef struct {
    /**
     * The CPU to fetch the trace of
     */
    uint16_t cpu_id;

    /**
     * The number of valid bytes of trace data in the buffer, offset from the start of the buffer. This can be used for
     * processing the trace data.
     * The kernel will place values at this location on success.
     */
    uint64_t *trace_packet_byte_count_out;

    /**
     * The true length of the allocated buffer. This can be used for mmap-ing the trace buffer.
     * The kernel will place values at this location on success.
     */
    uint64_t *trace_buffer_length_out;
} hb_driver_packet_get_trace_lengths;

#define HB_DRIVER_PACKET_IOC_GET_TRACE_LENGTHS _IOR(HB_DRIVER_PACKET_IOC_MAGIC, 4, hb_driver_packet_get_trace_lengths)


#endif //HONEY_DRIVER_HB_DRIVER_PACKETS_H
