//
// Created by Allison Husain on 1/10/21.
//

#ifndef HONEY_DRIVER_HONEY_DRIVER_CONSTANTS_H
#define HONEY_DRIVER_HONEY_DRIVER_CONSTANTS_H

#define MSR_IA32_RTIT_OUTPUT_BASE    0x00000560
#define MSR_IA32_RTIT_OUTPUT_MASK_PTRS    0x00000561
#define MSR_IA32_RTIT_CTL        0x00000570
#define TRACE_EN    BIT_ULL(0)
#define CYC_EN        BIT_ULL(1)
#define CTL_OS        BIT_ULL(2)
#define CTL_USER    BIT_ULL(3)
#define PT_ERROR    BIT_ULL(4)
#define CR3_FILTER    BIT_ULL(7)
#define PWR_EVT_EN    BIT_ULL(4)
#define FUP_ON_PTW_EN    BIT_ULL(5)
#define TO_PA        BIT_ULL(8)
#define MTC_EN        BIT_ULL(9)
#define TSC_EN        BIT_ULL(10)
#define DIS_RETC    BIT_ULL(11)
#define PTW_EN        BIT_ULL(12)
#define BRANCH_EN    BIT_ULL(13)
#define MTC_MASK    (0xf << 14)
#define CYC_MASK    (0xf << 19)
#define PSB_MASK    (0xf << 24)
#define ADDRn_SHIFT(n) (32 + (4*(n)))
#define ADDRn_MASK (0xfULL << ADDRn_SHIFT(n))
#define MSR_IA32_RTIT_STATUS        0x00000571
#define MSR_IA32_CR3_MATCH        0x00000572
#define TOPA_STOP    BIT_ULL(4)
#define TOPA_INT    BIT_ULL(2)
#define TOPA_END    BIT_ULL(0)
#define TOPA_SIZE_SHIFT 6
#define MSR_IA32_ADDRn_START(n) (0x00000580 + 2*(n))
#define MSR_IA32_ADDRn_END(n) (0x00000581 + 2*(n))

enum HB_DRIVER_TRACE_STATUS {
    HB_DRIVER_TRACE_STATUS_IDLE = 0x0,
    HB_DRIVER_TRACE_STATUS_TRACING = 0x1,
    HB_DRIVER_TRACE_STATUS_CORE_NOT_CONFIGURED = 0x2,
    /* error states */
    HB_DRIVER_TRACE_STATUS_CONFIGURATION_WRITE_ERROR = 0x3,

};


#endif //HONEY_DRIVER_HONEY_DRIVER_CONSTANTS_H
