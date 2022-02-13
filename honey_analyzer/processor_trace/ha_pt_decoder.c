//
// Created by Allison Husain on 12/29/20.
//

/*
 NOTE: This decoder was heavily inspired by libxdc. Parts of libxdc were borrowed directly while other while others
 were rewritten using ideas learned from libxdc. libxdc is available under the MIT license and is available in full at
 https://github.com/nyx-fuzz/libxdc/blob/master/LICENSE

***

Copyright (c) 2020 Sergej Schumilo, Cornelius Aschermann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

#include "ha_pt_decoder.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../ha_debug_switch.h"
#include "ha_pt_decoder_constants.h"
#if HA_ENABLE_DECODER_LOGS
#define LOGGER(format, ...) (printf("[" __FILE__ "] " format, ##__VA_ARGS__))
#else
#define LOGGER(format, ...)  (void)0
#endif
#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)



static uint8_t psb[16] = {
        0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
        0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82
};

#define TAG "[" __FILE__"] "

ha_pt_decoder_t ha_pt_decoder_alloc(void) {
    return calloc(1, sizeof(ha_pt_decoder));
}

void ha_pt_decoder_free(ha_pt_decoder_t decoder) {
    if (!decoder) {
        return;
    }

    free(decoder);
}

void ha_pt_decoder_reconfigure_with_trace(ha_pt_decoder_t decoder, uint8_t *trace_buffer, uint64_t trace_length) {
    /* clear all state (including our embedded cache) */
    bzero(decoder, sizeof(ha_pt_decoder));

    decoder->pt_buffer = trace_buffer;
    decoder->i_pt_buffer = trace_buffer;
    decoder->pt_buffer_length = trace_length;
}


int ha_pt_decoder_sync_forward(ha_pt_decoder_t decoder) {
    uint8_t *pt_end_ptr = decoder->pt_buffer + decoder->pt_buffer_length - 1;
    for (uint8_t *ptr_i = decoder->i_pt_buffer; ptr_i < pt_end_ptr - PT_PKT_PSB_LEN; ptr_i++) {
        if (memcmp(ptr_i, psb, PT_PKT_PSB_LEN) == 0) {
            decoder->i_pt_buffer = ptr_i;
            return -HA_PT_DECODER_NO_ERROR;
        }
    }

    return -HA_PT_DECODER_COULD_NOT_SYNC;
}

void ha_pt_decoder_internal_get_trace_buffer(ha_pt_decoder_t decoder, uint8_t **trace, uint64_t *trace_length) {
    *trace = decoder->pt_buffer;
    *trace_length = decoder->pt_buffer_length;
}

/* *** Intel PT decode *** */

/** Returns true if the TNT cache can accept more TNT packets safely. */
__attribute__((always_inline))
static inline bool is_tnt_cache_near_full(ha_pt_decoder_t decoder) {
    //If we have fewer than 47 slots (aka the largest LTNT) we consider ourselves full so that we don't drop anything
    return HA_PT_DECODER_CACHE_TNT_COUNT - ha_pt_decoder_cache_tnt_count(&decoder->cache) < 47;
}

__attribute__((always_inline))
static inline uint64_t get_ip_val(uint8_t **pp, uint64_t *last_ip){
    register uint8_t len = (*(*pp)++ >> PT_PKT_TIP_SHIFT);
    if(unlikely(!len))
        return 0;
    uint64_t aligned_pp;
    memcpy(&aligned_pp, *pp, sizeof(uint64_t));

    *last_ip = ((int64_t)((uint64_t)(
            ((aligned_pp & (0xFFFFFFFFFFFFFFFF >> ((4-len)*16))) | (*last_ip & (0xFFFFFFFFFFFFFFFF << ((len)*16))) )
    )<< (64 - 48))) >> (64 - 48);

    *pp += (len*2);

    return *last_ip;
}

__attribute__((always_inline))
static inline bool tip_handler(ha_pt_decoder_t decoder) {
    decoder->cache.next_indirect_branch_target = get_ip_val(&decoder->i_pt_buffer, &decoder->last_tip);
    LOGGER("TIP    \t%p (TNT: %llu)\n", (void *)decoder->last_tip, ha_pt_decoder_cache_tnt_count(&decoder->cache));
    return false;
}

__attribute__((always_inline))
static inline bool tip_pge_handler(ha_pt_decoder_t decoder) {
    uint64_t last = decoder->last_tip;
    uint64_t result = get_ip_val(&decoder->i_pt_buffer, &decoder->last_tip);
    LOGGER("PGE    \t%p (TNT: %llu)\n", (void *)decoder->last_tip, ha_pt_decoder_cache_tnt_count(&decoder->cache));
    //We clear OVF state on PGE because it means that we have a new starting address and so will not take the FUP.
    decoder->is_in_ovf_state = 0;

    if (likely(last != result)) {
        decoder->cache.override_target = result;
        return false;
    }

    return true;
}

__attribute__((always_inline))
static inline bool tip_pgd_handler(ha_pt_decoder_t decoder) {
    get_ip_val(&decoder->i_pt_buffer, &decoder->last_tip);
    LOGGER("PGD    \t%p (TNT: %llu)\n", (void *)decoder->last_tip, ha_pt_decoder_cache_tnt_count(&decoder->cache));
    return true;
}

__attribute__((always_inline))
static inline bool tip_fup_handler(ha_pt_decoder_t decoder) {
//    uint64_t last = decoder->last_tip;
    uint64_t res = get_ip_val(&decoder->i_pt_buffer, &decoder->last_tip);

    //FIXME: ...do FUPs not matter? Enabling them actually CAUSES issues
    //We need to take an FUP when we have an overflow
    if (unlikely(decoder->is_in_ovf_state)) {
        LOGGER("FUP_OVF\t%p (TNT: %llu)\n", (void *)decoder->last_tip, ha_pt_decoder_cache_tnt_count
        (&decoder->cache));
        decoder->cache.override_target = res;
        return false;
    }

    LOGGER("FUP    \t%p (TNT: %llu)\n", (void *)decoder->last_tip, ha_pt_decoder_cache_tnt_count(&decoder->cache));
    return true;
}

__attribute__((always_inline))
static inline bool ovf_handler(ha_pt_decoder_t decoder) {
    LOGGER("OVF    \t@%p\n", (void *)(decoder->i_pt_buffer - decoder->pt_buffer));
    decoder->is_in_ovf_state = 1;
    return true;
}

static inline uint8_t asm_bsr(uint64_t x) {
#if __APPLE__
    return __builtin_clz(x) ^ 31;
#else
    asm ("bsrq %0, %0" : "=r" (x) : "0" (x));
    return x;
#endif
}

static inline bool append_tnt_cache(ha_pt_decoder_t decoder, uint8_t data) {
    uint8_t bits = asm_bsr(data)-SHORT_TNT_OFFSET;
    for (int16_t i = bits + SHORT_TNT_OFFSET - 1; i >= SHORT_TNT_OFFSET; i--) {
        uint8_t b = (data >> i) & 0b1;
        ha_pt_decoder_cache_tnt_push_back(&decoder->cache, b);
    }

    return !is_tnt_cache_near_full(decoder);
}

__attribute__((always_inline))
static inline bool append_tnt_cache_ltnt(ha_pt_decoder_t decoder, uint64_t data) {
    uint8_t bits = asm_bsr(data)-LONG_TNT_MAX_BITS;
    for (int16_t i = bits + LONG_TNT_MAX_BITS - 1; i >= LONG_TNT_MAX_BITS; i--) {
        uint8_t b = (data >> i) & 0b1;
        ha_pt_decoder_cache_tnt_push_back(&decoder->cache, b);
    }

    return !is_tnt_cache_near_full(decoder);
}


__attribute__((hot))
int ha_pt_decoder_decode_until_caches_filled(ha_pt_decoder_t decoder) {
    static void* dispatch_table_level_1[] = {
            __extension__ &&handle_pt_pad,        // 00000000
            __extension__ &&handle_pt_tip_pgd,    // 00000001
            __extension__ &&handle_pt_level_2,    // 00000010
            __extension__ &&handle_pt_cyc,        // 00000011
            __extension__ &&handle_pt_tnt8,        // 00000100
            __extension__ &&handle_pt_error,        // 00000101
            __extension__ &&handle_pt_tnt8,        // 00000110
            __extension__ &&handle_pt_cyc,        // 00000111
            __extension__ &&handle_pt_tnt8,        // 00001000
            __extension__ &&handle_pt_error,        // 00001001
            __extension__ &&handle_pt_tnt8,        // 00001010
            __extension__ &&handle_pt_cyc,        // 00001011
            __extension__ &&handle_pt_tnt8,        // 00001100
            __extension__ &&handle_pt_tip,        // 00001101
            __extension__ &&handle_pt_tnt8,        // 00001110
            __extension__ &&handle_pt_cyc,        // 00001111
            __extension__ &&handle_pt_tnt8,        // 00010000
            __extension__ &&handle_pt_tip_pge,    // 00010001
            __extension__ &&handle_pt_tnt8,        // 00010010
            __extension__ &&handle_pt_cyc,        // 00010011
            __extension__ &&handle_pt_tnt8,        // 00010100
            __extension__ &&handle_pt_error,        // 00010101
            __extension__ &&handle_pt_tnt8,        // 00010110
            __extension__ &&handle_pt_cyc,        // 00010111
            __extension__ &&handle_pt_tnt8,        // 00011000
            __extension__ &&handle_pt_tsc,        // 00011001
            __extension__ &&handle_pt_tnt8,        // 00011010
            __extension__ &&handle_pt_cyc,        // 00011011
            __extension__ &&handle_pt_tnt8,        // 00011100
            __extension__ &&handle_pt_tip_fup,    // 00011101
            __extension__ &&handle_pt_tnt8,        // 00011110
            __extension__ &&handle_pt_cyc,        // 00011111
            __extension__ &&handle_pt_tnt8,        // 00100000
            __extension__ &&handle_pt_tip_pgd,    // 00100001
            __extension__ &&handle_pt_tnt8,        // 00100010
            __extension__ &&handle_pt_cyc,        // 00100011
            __extension__ &&handle_pt_tnt8,        // 00100100
            __extension__ &&handle_pt_error,        // 00100101
            __extension__ &&handle_pt_tnt8,        // 00100110
            __extension__ &&handle_pt_cyc,        // 00100111
            __extension__ &&handle_pt_tnt8,        // 00101000
            __extension__ &&handle_pt_error,        // 00101001
            __extension__ &&handle_pt_tnt8,        // 00101010
            __extension__ &&handle_pt_cyc,        // 00101011
            __extension__ &&handle_pt_tnt8,        // 00101100
            __extension__ &&handle_pt_tip,        // 00101101
            __extension__ &&handle_pt_tnt8,        // 00101110
            __extension__ &&handle_pt_cyc,        // 00101111
            __extension__ &&handle_pt_tnt8,        // 00110000
            __extension__ &&handle_pt_tip_pge,    // 00110001
            __extension__ &&handle_pt_tnt8,        // 00110010
            __extension__ &&handle_pt_cyc,        // 00110011
            __extension__ &&handle_pt_tnt8,        // 00110100
            __extension__ &&handle_pt_error,        // 00110101
            __extension__ &&handle_pt_tnt8,        // 00110110
            __extension__ &&handle_pt_cyc,        // 00110111
            __extension__ &&handle_pt_tnt8,        // 00111000
            __extension__ &&handle_pt_error,        // 00111001
            __extension__ &&handle_pt_tnt8,        // 00111010
            __extension__ &&handle_pt_cyc,        // 00111011
            __extension__ &&handle_pt_tnt8,        // 00111100
            __extension__ &&handle_pt_tip_fup,    // 00111101
            __extension__ &&handle_pt_tnt8,        // 00111110
            __extension__ &&handle_pt_cyc,        // 00111111
            __extension__ &&handle_pt_tnt8,        // 01000000
            __extension__ &&handle_pt_tip_pgd,    // 01000001
            __extension__ &&handle_pt_tnt8,        // 01000010
            __extension__ &&handle_pt_cyc,        // 01000011
            __extension__ &&handle_pt_tnt8,        // 01000100
            __extension__ &&handle_pt_error,        // 01000101
            __extension__ &&handle_pt_tnt8,        // 01000110
            __extension__ &&handle_pt_cyc,        // 01000111
            __extension__ &&handle_pt_tnt8,        // 01001000
            __extension__ &&handle_pt_error,        // 01001001
            __extension__ &&handle_pt_tnt8,        // 01001010
            __extension__ &&handle_pt_cyc,        // 01001011
            __extension__ &&handle_pt_tnt8,        // 01001100
            __extension__ &&handle_pt_tip,        // 01001101
            __extension__ &&handle_pt_tnt8,        // 01001110
            __extension__ &&handle_pt_cyc,        // 01001111
            __extension__ &&handle_pt_tnt8,        // 01010000
            __extension__ &&handle_pt_tip_pge,    // 01010001
            __extension__ &&handle_pt_tnt8,        // 01010010
            __extension__ &&handle_pt_cyc,        // 01010011
            __extension__ &&handle_pt_tnt8,        // 01010100
            __extension__ &&handle_pt_exit,        // 01010101
            __extension__ &&handle_pt_tnt8,        // 01010110
            __extension__ &&handle_pt_cyc,        // 01010111
            __extension__ &&handle_pt_tnt8,        // 01011000
            __extension__ &&handle_pt_mtc,        // 01011001
            __extension__ &&handle_pt_tnt8,        // 01011010
            __extension__ &&handle_pt_cyc,        // 01011011
            __extension__ &&handle_pt_tnt8,        // 01011100
            __extension__ &&handle_pt_tip_fup,    // 01011101
            __extension__ &&handle_pt_tnt8,        // 01011110
            __extension__ &&handle_pt_cyc,        // 01011111
            __extension__ &&handle_pt_tnt8,        // 01100000
            __extension__ &&handle_pt_tip_pgd,    // 01100001
            __extension__ &&handle_pt_tnt8,        // 01100010
            __extension__ &&handle_pt_cyc,        // 01100011
            __extension__ &&handle_pt_tnt8,        // 01100100
            __extension__ &&handle_pt_error,        // 01100101
            __extension__ &&handle_pt_tnt8,        // 01100110
            __extension__ &&handle_pt_cyc,        // 01100111
            __extension__ &&handle_pt_tnt8,        // 01101000
            __extension__ &&handle_pt_error,        // 01101001
            __extension__ &&handle_pt_tnt8,        // 01101010
            __extension__ &&handle_pt_cyc,        // 01101011
            __extension__ &&handle_pt_tnt8,        // 01101100
            __extension__ &&handle_pt_tip,        // 01101101
            __extension__ &&handle_pt_tnt8,        // 01101110
            __extension__ &&handle_pt_cyc,        // 01101111
            __extension__ &&handle_pt_tnt8,        // 01110000
            __extension__ &&handle_pt_tip_pge,    // 01110001
            __extension__ &&handle_pt_tnt8,        // 01110010
            __extension__ &&handle_pt_cyc,        // 01110011
            __extension__ &&handle_pt_tnt8,        // 01110100
            __extension__ &&handle_pt_error,        // 01110101
            __extension__ &&handle_pt_tnt8,        // 01110110
            __extension__ &&handle_pt_cyc,        // 01110111
            __extension__ &&handle_pt_tnt8,        // 01111000
            __extension__ &&handle_pt_error,        // 01111001
            __extension__ &&handle_pt_tnt8,        // 01111010
            __extension__ &&handle_pt_cyc,        // 01111011
            __extension__ &&handle_pt_tnt8,        // 01111100
            __extension__ &&handle_pt_tip_fup,    // 01111101
            __extension__ &&handle_pt_tnt8,        // 01111110
            __extension__ &&handle_pt_cyc,        // 01111111
            __extension__ &&handle_pt_tnt8,        // 10000000
            __extension__ &&handle_pt_tip_pgd,    // 10000001
            __extension__ &&handle_pt_tnt8,        // 10000010
            __extension__ &&handle_pt_cyc,        // 10000011
            __extension__ &&handle_pt_tnt8,        // 10000100
            __extension__ &&handle_pt_error,        // 10000101
            __extension__ &&handle_pt_tnt8,        // 10000110
            __extension__ &&handle_pt_cyc,        // 10000111
            __extension__ &&handle_pt_tnt8,        // 10001000
            __extension__ &&handle_pt_error,        // 10001001
            __extension__ &&handle_pt_tnt8,        // 10001010
            __extension__ &&handle_pt_cyc,        // 10001011
            __extension__ &&handle_pt_tnt8,        // 10001100
            __extension__ &&handle_pt_tip,        // 10001101
            __extension__ &&handle_pt_tnt8,        // 10001110
            __extension__ &&handle_pt_cyc,        // 10001111
            __extension__ &&handle_pt_tnt8,        // 10010000
            __extension__ &&handle_pt_tip_pge,    // 10010001
            __extension__ &&handle_pt_tnt8,        // 10010010
            __extension__ &&handle_pt_cyc,        // 10010011
            __extension__ &&handle_pt_tnt8,        // 10010100
            __extension__ &&handle_pt_error,        // 10010101
            __extension__ &&handle_pt_tnt8,        // 10010110
            __extension__ &&handle_pt_cyc,        // 10010111
            __extension__ &&handle_pt_tnt8,        // 10011000
            __extension__ &&handle_pt_mode,        // 10011001
            __extension__ &&handle_pt_tnt8,        // 10011010
            __extension__ &&handle_pt_cyc,        // 10011011
            __extension__ &&handle_pt_tnt8,        // 10011100
            __extension__ &&handle_pt_tip_fup,    // 10011101
            __extension__ &&handle_pt_tnt8,        // 10011110
            __extension__ &&handle_pt_cyc,        // 10011111
            __extension__ &&handle_pt_tnt8,        // 10100000
            __extension__ &&handle_pt_tip_pgd,    // 10100001
            __extension__ &&handle_pt_tnt8,        // 10100010
            __extension__ &&handle_pt_cyc,        // 10100011
            __extension__ &&handle_pt_tnt8,        // 10100100
            __extension__ &&handle_pt_error,        // 10100101
            __extension__ &&handle_pt_tnt8,        // 10100110
            __extension__ &&handle_pt_cyc,        // 10100111
            __extension__ &&handle_pt_tnt8,        // 10101000
            __extension__ &&handle_pt_error,        // 10101001
            __extension__ &&handle_pt_tnt8,        // 10101010
            __extension__ &&handle_pt_cyc,        // 10101011
            __extension__ &&handle_pt_tnt8,        // 10101100
            __extension__ &&handle_pt_tip,        // 10101101
            __extension__ &&handle_pt_tnt8,        // 10101110
            __extension__ &&handle_pt_cyc,        // 10101111
            __extension__ &&handle_pt_tnt8,        // 10110000
            __extension__ &&handle_pt_tip_pge,    // 10110001
            __extension__ &&handle_pt_tnt8,        // 10110010
            __extension__ &&handle_pt_cyc,        // 10110011
            __extension__ &&handle_pt_tnt8,        // 10110100
            __extension__ &&handle_pt_error,        // 10110101
            __extension__ &&handle_pt_tnt8,        // 10110110
            __extension__ &&handle_pt_cyc,        // 10110111
            __extension__ &&handle_pt_tnt8,        // 10111000
            __extension__ &&handle_pt_error,        // 10111001
            __extension__ &&handle_pt_tnt8,        // 10111010
            __extension__ &&handle_pt_cyc,        // 10111011
            __extension__ &&handle_pt_tnt8,        // 10111100
            __extension__ &&handle_pt_tip_fup,    // 10111101
            __extension__ &&handle_pt_tnt8,        // 10111110
            __extension__ &&handle_pt_cyc,        // 10111111
            __extension__ &&handle_pt_tnt8,        // 11000000
            __extension__ &&handle_pt_tip_pgd,    // 11000001
            __extension__ &&handle_pt_tnt8,        // 11000010
            __extension__ &&handle_pt_cyc,        // 11000011
            __extension__ &&handle_pt_tnt8,        // 11000100
            __extension__ &&handle_pt_error,        // 11000101
            __extension__ &&handle_pt_tnt8,        // 11000110
            __extension__ &&handle_pt_cyc,        // 11000111
            __extension__ &&handle_pt_tnt8,        // 11001000
            __extension__ &&handle_pt_error,        // 11001001
            __extension__ &&handle_pt_tnt8,        // 11001010
            __extension__ &&handle_pt_cyc,        // 11001011
            __extension__ &&handle_pt_tnt8,        // 11001100
            __extension__ &&handle_pt_tip,        // 11001101
            __extension__ &&handle_pt_tnt8,        // 11001110
            __extension__ &&handle_pt_cyc,        // 11001111
            __extension__ &&handle_pt_tnt8,        // 11010000
            __extension__ &&handle_pt_tip_pge,    // 11010001
            __extension__ &&handle_pt_tnt8,        // 11010010
            __extension__ &&handle_pt_cyc,        // 11010011
            __extension__ &&handle_pt_tnt8,        // 11010100
            __extension__ &&handle_pt_error,        // 11010101
            __extension__ &&handle_pt_tnt8,        // 11010110
            __extension__ &&handle_pt_cyc,        // 11010111
            __extension__ &&handle_pt_tnt8,        // 11011000
            __extension__ &&handle_pt_error,        // 11011001
            __extension__ &&handle_pt_tnt8,        // 11011010
            __extension__ &&handle_pt_cyc,        // 11011011
            __extension__ &&handle_pt_tnt8,        // 11011100
            __extension__ &&handle_pt_tip_fup,    // 11011101
            __extension__ &&handle_pt_tnt8,        // 11011110
            __extension__ &&handle_pt_cyc,        // 11011111
            __extension__ &&handle_pt_tnt8,        // 11100000
            __extension__ &&handle_pt_tip_pgd,    // 11100001
            __extension__ &&handle_pt_tnt8,        // 11100010
            __extension__ &&handle_pt_cyc,        // 11100011
            __extension__ &&handle_pt_tnt8,        // 11100100
            __extension__ &&handle_pt_error,        // 11100101
            __extension__ &&handle_pt_tnt8,        // 11100110
            __extension__ &&handle_pt_cyc,        // 11100111
            __extension__ &&handle_pt_tnt8,        // 11101000
            __extension__ &&handle_pt_error,        // 11101001
            __extension__ &&handle_pt_tnt8,        // 11101010
            __extension__ &&handle_pt_cyc,        // 11101011
            __extension__ &&handle_pt_tnt8,        // 11101100
            __extension__ &&handle_pt_tip,        // 11101101
            __extension__ &&handle_pt_tnt8,        // 11101110
            __extension__ &&handle_pt_cyc,        // 11101111
            __extension__ &&handle_pt_tnt8,        // 11110000
            __extension__ &&handle_pt_tip_pge,    // 11110001
            __extension__ &&handle_pt_tnt8,        // 11110010
            __extension__ &&handle_pt_cyc,        // 11110011
            __extension__ &&handle_pt_tnt8,        // 11110100
            __extension__ &&handle_pt_error,        // 11110101
            __extension__ &&handle_pt_tnt8,        // 11110110
            __extension__ &&handle_pt_cyc,        // 11110111
            __extension__ &&handle_pt_tnt8,        // 11111000
            __extension__ &&handle_pt_error,        // 11111001
            __extension__ &&handle_pt_tnt8,        // 11111010
            __extension__ &&handle_pt_cyc,        // 11111011
            __extension__ &&handle_pt_tnt8,        // 11111100
            __extension__ &&handle_pt_tip_fup,    // 11111101
            __extension__ &&handle_pt_tnt8,        // 11111110
            __extension__ &&handle_pt_error,        // 11111111
    };

#define DISPATCH_L1 goto *dispatch_table_level_1[decoder->i_pt_buffer[0]];
    DISPATCH_L1;
    handle_pt_mode:
        decoder->i_pt_buffer += PT_PKT_MODE_LEN;
        LOGGER("MODE\n");
        DISPATCH_L1;
    handle_pt_tip:
        if (unlikely(!tip_handler(decoder))) {
            return HA_PT_DECODER_NO_ERROR;
        }
        DISPATCH_L1;
    handle_pt_tip_pge:
        if (unlikely(!tip_pge_handler(decoder))) {
            return HA_PT_DECODER_NO_ERROR;
        }
        DISPATCH_L1;
    handle_pt_tip_pgd:
        if (unlikely(!tip_pgd_handler(decoder))) {
            return HA_PT_DECODER_NO_ERROR;
        }
        DISPATCH_L1;
    handle_pt_tip_fup:
        if (unlikely(!tip_fup_handler(decoder))) {
            return HA_PT_DECODER_NO_ERROR;
        }
        DISPATCH_L1;
    handle_pt_pad:
        while(unlikely(!(*(++decoder->i_pt_buffer)))){}
        DISPATCH_L1;
    handle_pt_tnt8:
        LOGGER("TNT 0x%x\n", *decoder->i_pt_buffer);
        bool cont = append_tnt_cache(decoder, (uint64_t)(*(decoder->i_pt_buffer)));
        decoder->i_pt_buffer++;
        if (unlikely(!cont)) {
            return HA_PT_DECODER_NO_ERROR;
        }
        DISPATCH_L1;
    handle_pt_level_2:
    switch(decoder->i_pt_buffer[1]){
        case __extension__ 0b00000011:    /* CBR */
            decoder->i_pt_buffer += PT_PKT_CBR_LEN;
            DISPATCH_L1;

        case __extension__ 0b00100011:    /* PSBEND */
            decoder->i_pt_buffer += PT_PKT_PSBEND_LEN;
            LOGGER("PSBEND\n");
            DISPATCH_L1;

        case __extension__ 0b10000010:    /* PSB */
            decoder->i_pt_buffer += PT_PKT_PSB_LEN;
            LOGGER("PSB\n");
            DISPATCH_L1;

        case __extension__ 0b10100011:    /* LTNT */
            LOGGER("LTNT\n");
            bool cont = append_tnt_cache_ltnt(decoder, (uint64_t)*decoder->i_pt_buffer);
            decoder->i_pt_buffer += PT_PKT_LTNT_LEN;
            if (unlikely(!cont)) {
                return HA_PT_DECODER_NO_ERROR;
            }
            DISPATCH_L1;

        case __extension__ 0b11110011:    /* OVF */
            ovf_handler(decoder);
            decoder->i_pt_buffer += PT_PKT_OVF_LEN;
            DISPATCH_L1;

        case __extension__ 0b01000011:    /* PIP -- ignoring because we don't care about kernel */
        case __extension__ 0b10000011:    /* TS  -- ignoring because I have no idea what this is */
        case __extension__ 0b11001000:    /* VMCS -- ignoring because VM*/
        case __extension__ 0b11000011:    /* MNT -- ignoring because I also don't know what this is */
        case __extension__ 0b01110011:    /* TMA -- ignoring because we don't support time */
        default:
            return -HA_PT_DECODER_UNSUPPORTED_TRACE_PACKET;
    }

    handle_pt_mtc: /* ignoring because we don't support time */
    handle_pt_tsc: /* ignoring because we don't support time */
    handle_pt_cyc: /* ignoring because we don't support time */
    handle_pt_error: /* just an error */
        return -HA_PT_DECODER_UNSUPPORTED_TRACE_PACKET;

    handle_pt_exit:
        //We hit the stop codon
        return -HA_PT_DECODER_END_OF_STREAM;

#undef DISPATCH_L1
}