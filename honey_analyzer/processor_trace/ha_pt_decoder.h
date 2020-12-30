//
// Created by Allison Husain on 12/29/20.
//

#ifndef HONEY_ANALYZER_HA_PT_DECODER_H
#define HONEY_ANALYZER_HA_PT_DECODER_H
#include <stdlib.h>

typedef struct internal_ha_pt_decoder * ha_pt_decoder_t;

typedef enum {
    HA_PT_DECODER_NO_ERROR = 0, /* No error */
    HA_PT_DECODER_END_OF_STREAM = 1, /* The trace ended. This is not an error but rather an indication to stop */
    HA_PT_DECODER_INTERNAL = 2, /* idk */
    HA_PT_DECODER_COULD_NOT_SYNC = 3, /* The requested PSB could not be found */
    HA_PT_DECODER_TRACE_DESYNC = 4, /* An operation was requested which could not be completed given the trace */
    HA_PT_UNSUPPORTED_TRACE_PACKET = 5, /* An unsupported packet was found in the PT stream. Trace abort. */
} ha_pt_decoder_status;

typedef struct {
    /** If an indirect branch target is available, this field is non-zero. This may be an override. */
    uint64_t next_indirect_branch_target;
    uint64_t override_target;

    /** The next index for the TNT */
    uint64_t tnt_cache_index;

    /** The total number of valid entries in the TNT cache */
    uint64_t tnt_cache_count;

    /* KEEPS THESE LAST FOR CACHE SAKE */

    /**
     * The actual TNT cache. Index 0 is the first branch answer, etc.
     */
    uint8_t tnt_cache[1000];
} ha_pt_decoder_cache;

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

///** Get a pointer to the cache struct. You do not own this pointer, however you may consume data from it and should
// * modify it
ha_pt_decoder_cache *ha_pt_decoder_get_cache_ptr(ha_pt_decoder_t decoder);

/** Runs the decode process until one of the two caches fills */
int ha_pt_decoder_decode_until_caches_filled(ha_pt_decoder_t decoder);


/* ha_pt_decoder_cache functions -- these are defined here for inline-ability */

#define unlikely(x)     __builtin_expect((x),0)
#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

/**
 * Query the decoder for the next TNT. This function will trigger additional analysis if necessary.
 * @param fup_override If there was an FUP which must be taken instead of the expected TNT, fup_override will hold
 * the virtual address to continue decoding at.
 * @return 0 if the branch was not taken. 1 if the branch was taken. 2 if there was an FUP. A return value less than
 * zero indicates an error.
 */
 __attribute__((always_inline))
static inline int ha_pt_decoder_cache_query_tnt(ha_pt_decoder_t decoder, uint64_t *override) {
    ha_pt_decoder_cache *cache = ha_pt_decoder_get_cache_ptr(decoder);
    if (unlikely(cache->tnt_cache_index >= cache->tnt_cache_count)) {
        int refill_result = ha_pt_decoder_decode_until_caches_filled(decoder);
        if (unlikely(refill_result < 0 && refill_result != -HA_PT_DECODER_END_OF_STREAM)) {
            return refill_result;
        }

        //We tried to refill the cache but no TNTs were returned. This indicates that the consumer consumed data from
        // us in the wrong order.
        if (unlikely(cache->tnt_cache_count == 0)) {
            if (cache->override_target) {
                *override = cache->override_target;
                cache->override_target = 0;
                return 2;
            } else {
                return -HA_PT_DECODER_TRACE_DESYNC;
            }
        }
    }

    return cache->tnt_cache[cache->tnt_cache_index++];
}

/**
 * Query the decoder for where to go for an indirect jump.
 * @param ip A pointer to where the new IP should be placed.
 * @return Negative on error. 0 if an indirect branch was placed. 1 if there was an override.
 */
__attribute__((always_inline))
static inline int ha_pt_decoder_cache_query_indirect(ha_pt_decoder_t decoder, uint64_t *ip) {
    ha_pt_decoder_cache *cache = ha_pt_decoder_get_cache_ptr(decoder);
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

#endif //HONEY_ANALYZER_HA_PT_DECODER_H
