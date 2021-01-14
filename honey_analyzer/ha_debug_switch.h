//
// Created by Allison Husain on 12/30/20.
//

#ifndef HONEY_MIRROR_HA_DEBUG_SWITCH_H
#define HONEY_MIRROR_HA_DEBUG_SWITCH_H

/*
 * This file contains global debug logging switches
 */
/** Controls debug logging in ha_pt_decoder */
#define HA_ENABLE_DECODER_LOGS 0
/** Controls debug logging in ha_pt_session */
#define HA_ENABLE_ANALYSIS_LOGS 0
/** Controls block logging for both print blocks and unit tests. Disable this for performance tests. */
#define HA_ENABLE_BLOCK_LEVEL_LOGS 0
#define HA_BLOCK_REPORTS_ARE_EDGE_TRANSITIONS 1
#endif //HONEY_MIRROR_HA_DEBUG_SWITCH_H
