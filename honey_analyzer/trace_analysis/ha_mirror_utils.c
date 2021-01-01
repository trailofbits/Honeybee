//
// Created by Allison Husain on 12/23/20.
//

#include "ha_mirror_utils.h"


uint64_t ha_mirror_utils_convert_unslid_to_offset(uint64_t unslid_ip) {
    uint64_t index = unslid_ip - ha_mirror_direct_map_address_slide;
    if (index >= ha_mirror_direct_map_count) {
        //OOB
        return UINT64_MAX;
    }

    return (&ha_mirror_direct_map_START)[index];
}