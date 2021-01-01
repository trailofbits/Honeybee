//
// Created by Allison Husain on 12/23/20.
//

#ifndef HONEY_ANALYSIS_HA_MIRROR_UTILS_H
#define HONEY_ANALYSIS_HA_MIRROR_UTILS_H
#include "ha_session.h"

/**
 * A function which the block decoder will call whenever it encounters a block
 */
typedef void (ha_mirror_on_block_function)(ha_session_t session, uint64_t unslid_ip);

/**
 * This is defined in the mirror output assembly file.
 * Initiate block level decoding of a given
 * @param session The session to decode blocks from
 * @return A libipt status code
 */
extern int ha_mirror_block_decode(ha_session_t session) asm ("_ha_mirror_block_decode");

/**
 * The mirror contains a 1:1 mapping of each byte of code to a __TEXT offset.
 * These offsets cannot be understood/used in C, however the values may still be used for testing
 */
extern uint32_t ha_mirror_direct_map_START asm("_ha_mirror_direct_map");

/**
 * The number of entries in the table.
 */
extern uint64_t ha_mirror_direct_map_count asm("_ha_mirror_direct_map_count");

/**
 * The value by which each slid virtual IP is re-slid to get the index.
 * Subtract this value from a slid virtual IP to get the direct map index.
 */
extern uint64_t ha_mirror_direct_map_address_slide asm("_ha_mirror_direct_map_address_slide");


/**
 * For a given un-slid virtual IP, fetch the corresponding __TEXT offset
 * @param unslid_ip The unslid IP
 * @return The offset UINT64_MAX if not found.
 */
uint64_t ha_mirror_utils_convert_unslid_to_offset(uint64_t unslid_ip);



#endif //HONEY_ANALYSIS_HA_MIRROR_UTILS_H
