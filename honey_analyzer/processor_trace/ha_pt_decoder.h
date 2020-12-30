//
// Created by Allison Husain on 12/29/20.
//

#ifndef HONEY_ANALYZER_HA_PT_DECODER_H
#define HONEY_ANALYZER_HA_PT_DECODER_H
#include <stdlib.h>

#define HA_PT_HAS_FUP_PENDING (1LLU << 63)

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
    /** If an FUP was detected, it should be taken at the next query. An FUP is available with this field is non-zero */
    uint64_t pending_fup;

    /** The bit index of the next TNT. Note that this is NOT the index into tnt_cache, it's the BIT. */
    uint64_t tnt_cache_bit_position;
    /** The total number of valid bits in tnt_cache */
    uint64_t tnt_cache_bit_count;

    /** The index of the next indirect mask */
    uint64_t indirect_mask_index;
    /** The total number of valid masks in the cache */
    uint64_t indirect_mask_count;

    /* KEEPS THESE LAST FOR CACHE SAKE */

    /**
     * The actual TNT cache. Bit 0 of bucket 0 is the newest, bit 1 of bucket 0 is the second newest...
     * This is a circular buffer.
     */
    uint8_t tnt_cache[10000];

    /**
     * The actual cache of masks. Index 0 is the newest.
     * This is a circular buffer.
     */
    uint64_t indirect_mask_cache[1000];
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
static inline int ha_pt_decoder_cache_query_tnt(ha_pt_decoder_t decoder, uint64_t *fup_override) {
    ha_pt_decoder_cache *cache = ha_pt_decoder_get_cache_ptr(decoder);
    if (unlikely(cache->tnt_cache_bit_count == 0)) {
        int refill_result = ha_pt_decoder_decode_until_caches_filled(decoder);
        if (unlikely(refill_result < 0 && refill_result != -HA_PT_DECODER_END_OF_STREAM)) {
            return refill_result;
        }

        //We tried to refill the cache but no TNTs were returned. This indicates that the consumer consumed data from
        // us in the wrong order.
        if (unlikely(cache->tnt_cache_bit_count == 0)) {
            return -HA_PT_DECODER_TRACE_DESYNC;
        }
    }

    if (cache->pending_fup) {
        *fup_override = cache->pending_fup;
        cache->pending_fup = 0;
        return 2; /* indicate that we took an FUP override */
    }

    //Find our bucket and then our index inside that bucket
    uint64_t bucket = cache->tnt_cache_bit_position / 8;
    uint8_t bit_index = cache->tnt_cache_bit_position % 8;

    //We're consuming this bit, advance
    cache->tnt_cache_bit_position++;
    cache->tnt_cache_bit_count--;

    return (cache->tnt_cache[bucket % COUNT_OF(cache->tnt_cache)] >> bit_index) & 0b1;
}

/**
 * Query the decoder for where to go for an indirect jump.
 * @param ip A pointer to where the new IP should be placed.
 * @return Negative on error. 0 if an indirect branch was placed. 1 if there was an FUP.
 */
__attribute__((always_inline))
static inline int ha_pt_decoder_cache_query_indirect(ha_pt_decoder_t decoder, uint64_t *ip) {
    ha_pt_decoder_cache *cache = ha_pt_decoder_get_cache_ptr(decoder);
    if (unlikely(cache->indirect_mask_count == 0)) {
        int refill_result = ha_pt_decoder_decode_until_caches_filled(decoder);
        if (unlikely(refill_result < 0 && refill_result != -HA_PT_DECODER_END_OF_STREAM)) {
            return refill_result;
        }

        //We tried to refill the cache but no indirects were returned.
        // This indicates that the consumer consumed data from us in the wrong order.
        if (unlikely(cache->indirect_mask_count == 0)) {
            return -HA_PT_DECODER_TRACE_DESYNC;
        }
    }

    if (cache->pending_fup) {
        *ip = cache->pending_fup;
        cache->pending_fup = 0;
        return 1; /* indicate that we took an FUP override */
    }

    *ip = cache->indirect_mask_cache[(cache->indirect_mask_index++) % COUNT_OF(cache->indirect_mask_cache)];
    cache->indirect_mask_count--;
    return 0;
}

#undef unlikely

#endif //HONEY_ANALYZER_HA_PT_DECODER_H
