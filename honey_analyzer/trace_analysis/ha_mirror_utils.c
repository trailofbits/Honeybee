//
// Created by Allison Husain on 12/23/20.
//

#include "ha_mirror_utils.h"


uint64_t ha_mirror_utils_convert_unslid_to_code(uint64_t unslid_ip) {
    uint64_t *_unslid_virtual_ip_to_text = &ha_mirror_unslid_virtual_ip_to_text_START;

    uint64_t left = 0;
    uint64_t right = ha_mirror_unslid_virtual_ip_to_text_count;

    while (left <= right) {
        uint64_t search = (left + right) / 2;
        uint64_t unslid_address = _unslid_virtual_ip_to_text[search * 2];
        if (unslid_address <= unslid_ip
            && unslid_ip < _unslid_virtual_ip_to_text[(search + 1) * 2]) {
            return _unslid_virtual_ip_to_text[search * 2 + 1];
        } else if (unslid_ip < unslid_address) {
            right = search - 1;
        } else {
            left = search + 1;
        }
    }

    return 0;
}