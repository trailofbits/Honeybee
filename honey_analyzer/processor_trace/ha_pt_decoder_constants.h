//
// Created by Allison Husain on 1/12/21.
//

#ifndef HA_PT_DECODER_CONSTANTS_H
#define HA_PT_DECODER_CONSTANTS_H


/* This PSB begin pattern repeats 8 times, forming a 16 byte sequence */
#define PSB_BEGIN_PATTERN_0 0b01000000
#define PSB_BEGIN_PATTERN_1 0b01000001

/* This is a two byte sequence */
#define PSB_END_PATTERN_0 0b01000000
#define PSB_END_PATTERN_1 0b11000100

#define PT_TRACE_END            __extension__ 0b01010101

#define PT_PKT_GENERIC_LEN        2
#define PT_PKT_GENERIC_BYTE0    __extension__ 0b00000010

#define PT_PKT_LTNT_LEN            8
#define PT_PKT_LTNT_BYTE0        PT_PKT_GENERIC_BYTE0
#define PT_PKT_LTNT_BYTE1        __extension__ 0b10100011

#define PT_PKT_PIP_LEN            8
#define PT_PKT_PIP_BYTE0        PT_PKT_GENERIC_BYTE0
#define PT_PKT_PIP_BYTE1        __extension__ 0b01000011

#define PT_PKT_CBR_LEN            4
#define PT_PKT_CBR_BYTE0        PT_PKT_GENERIC_BYTE0
#define PT_PKT_CBR_BYTE1        __extension__ 0b00000011

#define PT_PKT_OVF_LEN            2
#define PT_PKT_OVF_BYTE0        PT_PKT_GENERIC_BYTE0
#define PT_PKT_OVF_BYTE1        __extension__ 0b11110011

#define PT_PKT_PSB_LEN            16
#define PT_PKT_PSB_BYTE0        PT_PKT_GENERIC_BYTE0
#define PT_PKT_PSB_BYTE1        __extension__ 0b10000010

#define PT_PKT_PSBEND_LEN        2
#define PT_PKT_PSBEND_BYTE0        PT_PKT_GENERIC_BYTE0
#define PT_PKT_PSBEND_BYTE1        __extension__ 0b00100011

#define PT_PKT_MNT_LEN            11
#define PT_PKT_MNT_BYTE0        PT_PKT_GENERIC_BYTE0
#define PT_PKT_MNT_BYTE1        __extension__ 0b11000011
#define PT_PKT_MNT_BYTE2        __extension__ 0b10001000

#define PT_PKT_TMA_LEN            7
#define PT_PKT_TMA_BYTE0        PT_PKT_GENERIC_BYTE0
#define PT_PKT_TMA_BYTE1        __extension__ 0b01110011

#define PT_PKT_VMCS_LEN            7
#define PT_PKT_VMCS_BYTE0        PT_PKT_GENERIC_BYTE0
#define PT_PKT_VMCS_BYTE1        __extension__ 0b11001000

#define    PT_PKT_TS_LEN            2
#define PT_PKT_TS_BYTE0            PT_PKT_GENERIC_BYTE0
#define PT_PKT_TS_BYTE1            __extension__ 0b10000011

#define PT_PKT_MODE_LEN            2
#define PT_PKT_MODE_BYTE0        __extension__ 0b10011001

#define PT_PKT_TIP_LEN            8
#define PT_PKT_TIP_SHIFT        5
#define PT_PKT_TIP_MASK            __extension__ 0b00011111
#define PT_PKT_TIP_BYTE0        __extension__ 0b00001101
#define PT_PKT_TIP_PGE_BYTE0    __extension__ 0b00010001
#define PT_PKT_TIP_PGD_BYTE0    __extension__ 0b00000001
#define PT_PKT_TIP_FUP_BYTE0    __extension__ 0b00011101


#define TIP_VALUE_0                (0x0<<5)
#define TIP_VALUE_1                (0x1<<5)
#define TIP_VALUE_2                (0x2<<5)
#define TIP_VALUE_3                (0x3<<5)
#define TIP_VALUE_4                (0x4<<5)
#define TIP_VALUE_5                (0x5<<5)
#define TIP_VALUE_6                (0x6<<5)
#define TIP_VALUE_7                (0x7<<5)

#define SHORT_TNT_OFFSET    1
#define SHORT_TNT_MAX_BITS    8-1-SHORT_TNT_OFFSET

#define LONG_TNT_OFFSET        16
#define LONG_TNT_MAX_BITS    64-1-LONG_TNT_OFFSET
#define BIT(x)                (1ULL << (x))

#endif //HA_PT_DECODER_CONSTANTS_H
