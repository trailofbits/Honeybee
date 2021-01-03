//
// Created by Allison Husain on 12/29/20.
//

#ifndef HONEY_ANALYZER_HA_PT_DECODER_H
#define HONEY_ANALYZER_HA_PT_DECODER_H
#include <stdlib.h>
#include <stdint.h>

typedef struct internal_ha_pt_decoder * ha_pt_decoder_t;

typedef enum {
    /** No error */
    HA_PT_DECODER_NO_ERROR = 0,
    /** The trace ended. This is not an error but rather an indication to stop */
    HA_PT_DECODER_END_OF_STREAM = 1,
    /** There was an internal decoder error. Probably not your fault. */
    HA_PT_DECODER_INTERNAL = 2,
    /** A sync operation failed because the target PSB could not be found. */
    HA_PT_DECODER_COULD_NOT_SYNC = 3,
    /**
     * An operation was requested which could not be completed given the trace.
     * This can mean one of three things:
     * 1. The decoder is buggy
     * 2. The analysis is buggy
     * 3. The mapping between the binary and the decoder is incorrect (leading to bad analysis)
     */
    HA_PT_DECODER_TRACE_DESYNC = 4,
    /** An unsupported packet was found in the PT stream. */
    HA_PT_UNSUPPORTED_TRACE_PACKET = 5,
    /** This is used by the mirror to communicate invalid jump targets. */
    HA_PT_INVALID_ADDRESS = 6,
} ha_pt_decoder_status;

/** The number of elements our cache struct holds. This is a power of two so we can mask instead of modulo */
#define HA_PT_DECODER_CACHE_TNT_COUNT (1LLU<<16U)
#define HA_PT_DECODER_CACHE_TNT_COUNT_MASK (HA_PT_DECODER_CACHE_TNT_COUNT - 1)
typedef struct {
    /** If an indirect branch target is available, this field is non-zero.*/
    uint64_t next_indirect_branch_target;
    /** If an event provided a new target, it should be taken before the indirect branch as an override. */
    uint64_t override_target;

    /*
     * The TNT cache uses a technique where we allow the read and write indices to overflow. Since they are signed,
     * this is defined. Since we define our cache size as a power of two, we can easily mask these values to get our
     * fitting value. We do all of this since it greatly simplifies all operations without complicated pointer
     * index arithmetic.
     */

    /** The next index for the TNT */
    uint64_t tnt_cache_read;
    /** The index to place the next TNT (i.e. there is no valid TNT here) */
    uint64_t tnt_cache_write;

    /**
     * The actual TNT cache. TNT items are in a FIFO ringbuffer.
     */
    int8_t tnt_cache[HA_PT_DECODER_CACHE_TNT_COUNT];
} ha_pt_decoder_cache;

typedef struct internal_ha_pt_decoder {
    /**
     * The PT buffer. This needs to be mmaped into a larger map in which the stop codon is placed just after the last
     * byte of this buffer
     */
    uint8_t *pt_buffer;

    /** This size of the PT buffer. This does not include the stop codon. */
    uint64_t pt_buffer_length;

    /** The iterator pointer. This is used to "walk" the trace without destroying our handle. */
    uint8_t *i_pt_buffer;

    /** The last TIP. This is used for understanding future TIPs since they are masks on this value. */
    uint64_t last_tip;

    /** Do we have an unresolved OVF packet? */
    uint64_t is_in_ovf_state;

    /* KEEP THIS LAST FOR THE SAKE OF THE CACHE */
    /** The cache struct. This is exposed directly to clients. */
    ha_pt_decoder_cache cache;

} ha_pt_decoder;

/**
 * Creates a new decoder from a raw Intel Processor Trace dump
 * @param trace_path The path to the trace file
 * @return The tracer session or NULL
 */
ha_pt_decoder_t ha_pt_decoder_alloc(const char *trace_path);

/** Frees a decoder and all other owned resources. */
void ha_pt_decoder_free(ha_pt_decoder_t decoder);

/** Resets a decoder to the state it was just after _alloc. */
void ha_pt_decoder_reset(ha_pt_decoder_t decoder);

/** Sync the decoder forwards towards the first PSB. Returns -ha_pt_decoder_status on error. */
int ha_pt_decoder_sync_forward(ha_pt_decoder_t decoder);

/**
 * Get a pointer to the cache struct. You do not own this pointer, however you may consume data from it and should
 * update state appropriately using ha_pt_decoder_cache_xxxxxx methods.
 */
ha_pt_decoder_cache *ha_pt_decoder_get_cache_ptr(ha_pt_decoder_t decoder);

/**
 * Copies the internal trace buffer information. This is meant for testing, mostly.
 */
void ha_pt_decoder_internal_get_trace_buffer(ha_pt_decoder_t decoder, uint8_t **trace, uint64_t *trace_length);

/** Runs the decode process until one of the two caches fills */
int ha_pt_decoder_decode_until_caches_filled(ha_pt_decoder_t decoder);



#define unlikely(x)     __builtin_expect((x),0)

/* ha_pt_decoder_cache */

/** Is the TNT cache empty? */
__attribute__((always_inline))
static inline int ha_pt_decoder_cache_tnt_is_empty(ha_pt_decoder_cache *cache) {
    return cache->tnt_cache_read == cache->tnt_cache_write;
}

/** Pushes a new TNT item to the end of the ringbuffer. Does not check for capacity. */
__attribute__((always_inline))
static inline void ha_pt_decoder_cache_tnt_push_back(ha_pt_decoder_cache *cache, uint8_t tnt) {
    cache->tnt_cache[(cache->tnt_cache_write++) & HA_PT_DECODER_CACHE_TNT_COUNT_MASK] = tnt;
}

/** Pops the first TNT item from front of the ringbuffer. Does not check for availability. */
__attribute__((always_inline))
static inline uint8_t ha_pt_decoder_cache_tnt_pop(ha_pt_decoder_cache *cache) {
    return cache->tnt_cache[(cache->tnt_cache_read++) & HA_PT_DECODER_CACHE_TNT_COUNT_MASK];
}

/** Returns the number of valid items in the ringbuffer. */
__attribute__((always_inline))
static inline uint64_t ha_pt_decoder_cache_tnt_count(ha_pt_decoder_cache *cache) {
    //This may trigger an overflow, but in a defined and correct way
    return cache->tnt_cache_write - cache->tnt_cache_read;
}

/* ha_pt_decoder functions -- these are defined here for inline-ability */

/**
 * Query the decoder for the next TNT. This function will trigger additional analysis if necessary.
 * @param override If there was an FUP which must be taken instead of the expected TNT, fup_override will hold
 * the virtual address to continue decoding at.
 * @return 0 if the branch was not taken. 1 if the branch was taken. 2 if there was an FUP. A return value less than
 * zero indicates an error.
 */
 __attribute__((always_inline))
static inline int ha_pt_decoder_cache_query_tnt(ha_pt_decoder_t decoder, uint64_t *override) {
    ha_pt_decoder_cache *cache = &decoder->cache;
    if (unlikely(ha_pt_decoder_cache_tnt_is_empty(cache))) {
        int refill_result = ha_pt_decoder_decode_until_caches_filled(decoder);
        if (unlikely(refill_result < 0 && refill_result != -HA_PT_DECODER_END_OF_STREAM)) {
            return refill_result;
        }

        //We tried to refill the cache but no TNTs were returned.
        //This indicates that the consumer consumed data from us in the wrong order.
        if (unlikely(ha_pt_decoder_cache_tnt_is_empty(cache))) {
            if (cache->override_target) {
                *override = cache->override_target;
                cache->override_target = 0;
                return 2;
            } else {
                return -HA_PT_DECODER_TRACE_DESYNC;
            }
        }
    }

    return ha_pt_decoder_cache_tnt_pop(cache);
}

/**
 * Query the decoder for where to go for an indirect jump.
 * @param ip A pointer to where the new IP should be placed.
 * @return Negative on error. 0 if an indirect branch was placed. 1 if there was an override.
 */
__attribute__((always_inline))
static inline int ha_pt_decoder_cache_query_indirect(ha_pt_decoder_t decoder, uint64_t *ip) {
    ha_pt_decoder_cache *cache = &decoder->cache;
    REROUTE:
    if (cache->override_target) {
        *ip = cache->override_target;
        cache->override_target = 0;
        return 1;
    } else if (cache->next_indirect_branch_target) {
        *ip = cache->next_indirect_branch_target;
        cache->next_indirect_branch_target = 0;
        return 0;
    } else {
        //No answer, we need to hit the decoder
        int result = ha_pt_decoder_decode_until_caches_filled(decoder);
        if (unlikely(result < 0)) {
            return result;
        }

        if (unlikely(!cache->next_indirect_branch_target && !cache->override_target)) {
            return -HA_PT_DECODER_TRACE_DESYNC;
        }

        goto REROUTE;
    }
}

#undef unlikely
#undef HA_PT_DECODER_CACHE_TNT_COUNT_MASK
#endif //HONEY_ANALYZER_HA_PT_DECODER_H
