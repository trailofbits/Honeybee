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
 * @param initial_unslid_ip The initial IP to begin decoding from
 * @return A libipt status code
 */
extern int ha_mirror_block_decode(ha_session_t session, uint64_t initial_unslid_ip) asm ("_ha_mirror_block_decode");

/**
 * The mirror contains an un-slid virtual IP to __TEXT map.
 * This item is the first element of that table. Take the address of this to get a pointer to the table.
 * The table is laid out in memory as (K,V,K,V...). There are ha_mirror_unslid_virtual_ip_to_text_count real items in
 * the table, but there is an additional fake "max item" added to the end which is greater than all elements in the
 * table.
 */
extern uint64_t ha_mirror_unslid_virtual_ip_to_text_START asm("_ha_mirror_unslid_virtual_ip_to_text");

/**
 * The number of K,V pairs in the table. Does not include the maximum pair.
 */
extern uint64_t ha_mirror_unslid_virtual_ip_to_text_count asm("_ha_mirror_unslid_virtual_ip_to_text_count");

/**
 * For a given un-slid virtual IP, fetch the corresponding decoder block in the __TEXT segment
 * @param unslid_ip The unslid IP
 * @return The address of the decoder block or NULL if not found.
 */
uint64_t ha_mirror_utils_convert_unslid_to_code(uint64_t unslid_ip) asm("_ha_mirror_utils_convert_unslid_to_code");


#endif //HONEY_ANALYSIS_HA_MIRROR_UTILS_H
