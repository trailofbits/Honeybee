//
// Created by Allison Husain on 1/9/21.
//

/*
 * This driver was built using sources from simple-pt. This file, and all of its modifications, is licensed under the
 * same terms.
 *
 * Copyright (c) 2015, Intel Corporation
 * Author: Andi Kleen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Alternatively you can use this file under the GPLv2.
 */


#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/cpu.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/nodemask.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/dcache.h>
#include <linux/ctype.h>
#include <linux/syscore_ops.h>
#include <trace/events/sched.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <asm/processor-flags.h>
#include <linux/cpumask.h>

#include "../honeybee_shared/hb_driver_packets.h"
#include "honey_driver_constants.h"

#define TAG "[honey_driver] "
#define TAGI KERN_INFO TAG "[*] "
#define TAGE KERN_ERR TAG  "[!] "

/*
 * Globals
 */

/**
 * Spinlock to protect global configuration. This is taken at the start of all ioctls and mmap operations to protect
 * our state.
 */
static DEFINE_SPINLOCK(configuration_spinlock);

/**
 * The number of ToPA entries to allocate per CPU
 */
static uint32_t topa_buffer_count;

/**
 * The number of pages, as a power of 2, to allocate
 */
static uint8_t topa_page_order;

/**
 * The number of supported address ranges. This is configure by a call to intel_pt_hardware_support_preflight
 */
static uint8_t address_range_filter_count;

/**
 * This is used by the read_msr_on_cpu SMP function since there's no way to return from an SMP routine
 */
static uint64_t temp_msr_read_result;
static int temp_msr_read_return_code;

/**
 * Virtual address of the ToPA table for this CPU
 */
static DEFINE_PER_CPU(uint64_t
*, topa_cpu);

/**
 * The trace status of a given core
 */
static DEFINE_PER_CPU(enum HB_DRIVER_TRACE_STATUS, trace_state);

/*
 * Utilities
 */

// https://carteryagemann.com/pid-to-cr3.html
static uint64_t pid_to_cr3(int const pid) {
    unsigned long cr3_phys = 0;
    rcu_read_lock();
    {
        struct pid *pidp = find_vpid(pid);
        struct task_struct *task;
        struct mm_struct *mm;

        if (!pidp)
            goto out;
        task = pid_task(pidp, PIDTYPE_PID);
        if (task == NULL)
            goto out; // pid has no task_struct
        mm = task->mm;

        // mm can be NULL in some rare cases (e.g. kthreads)
        // when this happens, we should check active_mm
        if (mm == NULL) {
            mm = task->active_mm;
            if (mm == NULL)
                goto out; // this shouldn't happen, but just in case
        }

        cr3_phys = virt_to_phys((void *) mm->pgd);
    }
    out:
    rcu_read_unlock();
    return cr3_phys;
}

/**
 * Checks a given CPU's state and returns a suitable return code for that state
 * @return Negative if the CPU is in an error state.
 */
static inline int cpu_state_to_result(int cpu) {
    enum HB_DRIVER_TRACE_STATUS code = per_cpu(trace_state, cpu);
    if (code > 0x2 /* is an error code */) {
        return -(1LLU << 11 | code);
    }

    return 0;
}

/**
 * Checks if a CPU's trace buffer can be accessed safely
 * @return Negative if not allowed
 */
static inline int preflight_trace_buffer_userspace_access(int cpu) {
    if (per_cpu(trace_state, cpu) != HB_DRIVER_TRACE_STATUS_IDLE) {
        //You can't get the buffer if tracing is in progress or we haven't traced
        return -EBUSY;
    }

    //You can't get the buffer if it hasn't been allocated
    if (per_cpu(topa_cpu, cpu) == 0x0) {
        return -ENOSPC;
    }

    return 0;
}

/*
 * Implementation
 */

/**
 * Runs a function on a given
 * @param cpu The CPU ID to run on
 * @param func The function to return
 * @param arg The value to pass to the function
 * @return A status code, negative if error
 */
static int smp_do_on_cpu(int cpu, smp_call_func_t func, void *arg) {
    cpumask_var_t mask;

    if (!zalloc_cpumask_var(&mask, GFP_KERNEL)) {
        return -ENOMEM;
    }

    cpumask_set_cpu(cpu, (struct cpumask *) mask);

    on_each_cpu_mask((struct cpumask *) mask, func, arg, true);

    free_cpumask_var(mask);

    return 0;
}

/**
 * Installs the CPU's ToPA values into its MSRs. This must be called through SMP
 */
static void configure_topa_msrs_on_this_cpu(void *unused) {
    int status;
    uint64_t output_base;
    uint64_t ctl;

    status = HB_DRIVER_TRACE_STATUS_CONFIGURATION_WRITE_ERROR;

    /* Stop PT if it's running */
    if (rdmsrl_safe(MSR_IA32_RTIT_CTL, &ctl)) {
        goto ABORT;
    }

    if (ctl & TRACE_EN
        && wrmsrl_safe(MSR_IA32_RTIT_CTL, ctl & ~TRACE_EN)) {
        goto ABORT;
    }

    /* Install the new ToPA base */
    output_base = (uint64_t) __this_cpu_read(topa_cpu);
    if (output_base) {
        output_base = __pa(output_base);
    }

    if (wrmsrl_safe(MSR_IA32_RTIT_OUTPUT_BASE, output_base)
        || wrmsrl_safe(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, 0)) {
        goto ABORT;
    }

    status = HB_DRIVER_TRACE_STATUS_IDLE;

    ABORT:
    __this_cpu_write(trace_state, status);
}

/** Allocates a ToPA buffer for a CPU and installs it. Uses the global topa_page_order and topa_buffer_count. */
static int allocate_pt_buffer_on_cpu(int cpu) {
    uint64_t * topa;

    /* allocate topa */
    topa = per_cpu(topa_cpu, cpu);
    if (!topa) {
        int n;

        topa = (uint64_t *) __get_free_page(GFP_KERNEL | __GFP_ZERO);
        if (!topa) {
            printk(TAGE "cpu %d, Cannot allocate topa page\n", cpu);
            return -ENOMEM;
        }

        per_cpu(topa_cpu, cpu) = topa;

        /* create circular topa table */
        n = 0;
        for (; n < topa_buffer_count; n++) {
            uint8_t *buf = (void *) __get_free_pages(
                    GFP_KERNEL | __GFP_NOWARN | __GFP_ZERO,
                    topa_page_order);

            if (!buf) {
                printk(TAGE "Cannot allocate %d'th PT buffer for CPU %d, truncating this ToPA buffer\n", n, cpu);
                break;
            }

            topa[n] = __pa(buf) | (topa_page_order << TOPA_SIZE_SHIFT);
        }

        //This is important as we use it for both our count method and our free
        topa[n] = (uint64_t) __pa(topa) | TOPA_END; /* circular buffer */
    }

    //Install it
    return smp_do_on_cpu(cpu, configure_topa_msrs_on_this_cpu, 0x00);
}

/**
 * Frees the ToPA structures and buffers for a given core
 */
static void free_pt_buffer_on_cpu(int cpu) {
    uint64_t * topa;

    topa = per_cpu(topa_cpu, cpu);
    if (topa) {
        int j;

        for (j = 1; j < topa_buffer_count; j++) {
            if (topa[j] & TOPA_END) {
                break;
            }

            free_pages((unsigned long) __va(topa[j] & PAGE_MASK), topa_page_order);
        }

        free_page((uint64_t) topa);
        per_cpu(topa_cpu, cpu) = 0x0;
    }

    //Purge MSRs
    smp_do_on_cpu(cpu, configure_topa_msrs_on_this_cpu, 0x00);
}

static unsigned int get_topa_entry_count(int cpu) {
    uint64_t * topa = per_cpu(topa_cpu, cpu);
    int count;

    if (!topa) {
        return 0;
    }

    //Kinda a hack but we assume the table is well-formed and terminated
    for (count = 0; !(topa[count] & TOPA_END); count++);
    return count;
}

/**
 * Configures PT on the current CPU using a configuration struct. Use SMP to call this.
 * Sets a flag in __this_cpu(trace_state) >0x1 if there was an error configuring PT
 *
 * Assumes that PT is NOT running on this CPU. If it is, it is disabled and not re-enabled.
 */
static void configure_pt_on_this_cpu(void *arg) {
    uint64_t ctl;
    hb_driver_packet_configure_trace *configure_trace;
    int filter_apply_count;
    int i;
    int status;

    status = HB_DRIVER_TRACE_STATUS_CONFIGURATION_WRITE_ERROR;
    configure_trace = arg;

    if (rdmsrl_safe(MSR_IA32_RTIT_CTL, &ctl)) {
        goto EXIT;
    }

    if (ctl & TRACE_EN) {
        //Disable tracing while configuring
        if (wrmsrl_safe(MSR_IA32_RTIT_CTL, ctl & ~TRACE_EN)) {
            goto EXIT;
        }
    }

    ctl &= ~(TSC_EN | CTL_OS | CTL_USER | CR3_FILTER | DIS_RETC | TO_PA |
             CYC_EN | TRACE_EN | BRANCH_EN | CYC_EN | MTC_EN |
             MTC_EN | MTC_MASK | CYC_MASK | PSB_MASK | PT_ERROR);

    for (i = 0; i < HB_DRIVER_PACKET_CONFIGURE_TRACE_FILTER_COUNT; i++) {
        ctl &= ~ADDRn_SHIFT(i);
    }

    //Baseline configuration
    ctl |= CTL_USER | DIS_RETC | TO_PA | BRANCH_EN;

    //configure_pt_on_cpu stuffed this with the cr3. If it is zero, however, that indicates that cr3 filtering is
    // disabled
    if (configure_trace->pid) {
        ctl |= CR3_FILTER;

        if (IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION) && static_cpu_has(X86_FEATURE_PTI)) {
            configure_trace->pid |= 1 << PAGE_SHIFT;
        }
    }
    if (wrmsrl_safe(MSR_IA32_CR3_MATCH, configure_trace->pid)) {
        goto EXIT;
    }

    if (address_range_filter_count >= HB_DRIVER_PACKET_CONFIGURE_TRACE_FILTER_COUNT) {
        filter_apply_count = HB_DRIVER_PACKET_CONFIGURE_TRACE_FILTER_COUNT;
    } else {
        filter_apply_count = address_range_filter_count;
    }

    //We only apply the first n supported filters
    for (i = 0; i < filter_apply_count; i++) {
        hb_driver_packet_range_filter *filter = &configure_trace->filters[i];
        if (filter->enabled) {
            ctl |= 1LLU /* filter */ << ADDRn_SHIFT(i);
            if (wrmsrl_safe(MSR_IA32_ADDRn_START(i), filter->start_address)
                || wrmsrl_safe(MSR_IA32_ADDRn_END(i), filter->stop_address)) {
                goto EXIT;
            }
        }
    }

    if (wrmsrl_safe(MSR_IA32_RTIT_STATUS, 0ULL) //clear errors
        || wrmsrl_safe(MSR_IA32_RTIT_OUTPUT_MASK_PTRS, 0ULL) //reset our output pointers to the start
        || wrmsrl_safe(MSR_IA32_RTIT_CTL, ctl)) { //write out the config :)
        goto EXIT;
    }

    status = HB_DRIVER_TRACE_STATUS_IDLE;

    EXIT:
    __this_cpu_write(trace_state, status);
}

/**
 * Configures PT on a given CPU
 * @param cpu The CPU to trace on. Assumed to be a valid CPU index
 * @param configure_trace A pointer to the trace config
 * @return Negative on error
 */
static int configure_pt_on_cpu(int cpu, hb_driver_packet_configure_trace *configure_trace) {
    int result;
    uint64_t ucr3;

    if (configure_trace->pid) {
        if (!(ucr3 = pid_to_cr3((int) configure_trace->pid))) {
            return -ESRCH;
        }
    }

    //We stash the UCR3 value in the configure_trace structure. This is explained in the header but this is really
    // just an ugly hack since we don't want to create a second structure to pass it. Additionally, if no PID was
    // sent (i.e. pid=0), we pass that through to signal that CR3 filtering should not be enabled.
    configure_trace->pid = ucr3;

    if ((result = smp_do_on_cpu(cpu, configure_pt_on_this_cpu, configure_trace))) {
        return result;
    }

    return cpu_state_to_result(cpu);
}

/**
 * Sets tracing status on this CPU
 * @param arg Non-zero to enable tracing
 */
static void set_pt_enable_on_this_cpu(void *arg) {
    unsigned long long enable;
    int status;
    uint64_t ctl;

    enable = (!(unsigned long long) arg) - 1; /* This is all ones if enabled and all zeros if disabled */

    if (rdmsrl_safe(MSR_IA32_RTIT_CTL, &ctl)
        || wrmsrl_safe(MSR_IA32_RTIT_CTL, (ctl & ~TRACE_EN) | (enable & TRACE_EN))) {
        status = HB_DRIVER_TRACE_STATUS_CONFIGURATION_WRITE_ERROR;
    } else {
        status = HB_DRIVER_TRACE_STATUS_IDLE;
    }

    __this_cpu_write(trace_state, status);
}

/**
 * Reads a given MSR safely into temp_msr_read_result and temp_msr_read_return_code
 */
static void read_msr_on_this_cpu(void *arg) {
    uint32_t msr = (uint32_t) (uint64_t) arg;
    temp_msr_read_return_code = rdmsrl_safe(msr, &temp_msr_read_result);
}

/**
 * Reads an MSR from a specific CPU and returns the result
 * Warning: This is a race-y function. Do not call multiple concurrently.
 */
static int read_msr_on_cpu(int cpu, uint32_t msr, uint64_t *result) {
    smp_do_on_cpu(cpu, read_msr_on_this_cpu, (void *) (uint64_t) msr);
    *result = temp_msr_read_result;
    return temp_msr_read_return_code;
}

/**
 * Checks that all of our rigid PT requirements are satisfied. This fills any hardware state required globals.
 * Note, these requirements could be loosened given more time, but this driver was kinda a last minute bodge :(
 * @return Negative if PT is not fully supported on this hardware.
 */
static int intel_pt_hardware_support_preflight(void) {
    unsigned a, b, c, d;

    cpuid(0, &a, &b, &c, &d);
    if (a < 0x14) {
        printk(TAGE "Not enough CPUID support for PT\n");
        return -EIO;
    }
    cpuid_count(0x07, 0x0, &a, &b, &c, &d);
    if ((b & BIT(25)) == 0) {
        printk(TAGE "No PT support\n");
        return -EIO;
    }

    cpuid_count(0x14, 0x0, &a, &b, &c, &d);

    if (!(b & BIT(0))) {
        printk(TAGE "No CR3 filter support\n");
        return -EIO;
    }

    if (!(b & BIT(2))) {
        printk(TAGE "IP filtering is not supported\n");
        return -EIO;
    }

    if (!(c & BIT(0))) {
        printk(TAGE "No ToPA support\n");
        return -EIO;
    }

    if (!(c & BIT(1))) {
        printk(TAGE "ToPA does not support multiple entries\n");
        return -EIO;
    }

    cpuid_count(0x14, 0x1, &a, &b, &c, &d);
    address_range_filter_count = a & 0b111;

    return 0;
}

/**
 * Handles ioctls from userspace. Packets are defined in honeybee_shared/hb_driver_packets
 */
static long honey_driver_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    unsigned long flags;
    long result;

    //Take the configuration lock. All operations touch state and so we really need those to be serial.
    //A reader-writer lock could be used but that's honestly a bit more complicated than really necessary since we
    // don't really expect to have THAT many concurrent operations
    spin_lock_irqsave(&configuration_spinlock, flags);

    switch (cmd) {
        case HB_DRIVER_PACKET_IOC_CONFIGURE_BUFFERS: {
            hb_driver_packet_configure_buffers configure_buffers;
            int i;
            int cpu_count;

            printk(TAGI "ioctl -- configure_buffers\n");

            //XXX this doesn't actually work if you offline random cores in the middle (i.e. offline core 4 of 8) but
            // I'm choosing to ignore that because who offlines a CPU core while fuzzing??
            cpu_count = num_online_cpus();

            //You can't adjust allocations while any CPU is tracing
            for (i = 0; i < cpu_count; i++) {
                if (per_cpu(trace_state, i) == HB_DRIVER_TRACE_STATUS_TRACING) {
                    result = -EBUSY;
                    goto OUT;
                }
            }

            if (copy_from_user(&configure_buffers, (void *) arg, sizeof configure_buffers) != 0
                || configure_buffers.count > PAGE_SIZE - 1
                || configure_buffers.page_count_power == 0) {
                result = -EINVAL;
                goto OUT;
            }

            /* we don't actually allocate the buffers, but we will destroy existing ones before we change our config */
            //Allocate the buffer for each online CPU
            for (i = 0; i < cpu_count; i++) {
                //Free any existing allocations. This is a NOP if no buffers have been allocated
                free_pt_buffer_on_cpu(i);
            }

            /*
             * buffers are actually allocated on trace configure. This is because we only want to allocate buffers
             * for CPUs we're tracing on. Since our fuzzing load has us leave ~1/2 of the CPUs unused, it's
             * nonsensical to give each CPU a buffer.
             */
            topa_buffer_count = configure_buffers.count;
            topa_page_order = configure_buffers.page_count_power;

            result = 0;
            break;
        }
        case HB_DRIVER_PACKET_IOC_SET_ENABLED: {
            hb_driver_packet_set_enabled set_enabled;
            unsigned long long enabled_state;

            printk(TAGI "ioctl -- set_enabled\n");

            if (copy_from_user(&set_enabled, (void *) arg, sizeof set_enabled) != 0
                || !cpu_online(set_enabled.cpu_id)) {
                result = -EINVAL;
                goto OUT;
            }

            //First verify that we CAN launch this CPU
            //Are we in a valid state to enable PT?
            if (!(per_cpu(trace_state, set_enabled.cpu_id) == HB_DRIVER_TRACE_STATUS_IDLE
                  || per_cpu(trace_state, set_enabled.cpu_id) == HB_DRIVER_TRACE_STATUS_TRACING)) {
                result = -EPERM;
                goto OUT;
            }

            //Do we have the required buffer configured (note: we assume that if the buffers are allocated the MSRs
            // were correctly set).
            if (!per_cpu(topa_cpu, set_enabled.cpu_id)) {
                result = -ENOSPC;
                goto OUT;
            }

            /* we are safe to enable PT */
            enabled_state = set_enabled.enabled;
            smp_do_on_cpu(set_enabled.cpu_id, set_pt_enable_on_this_cpu, (void *) enabled_state);

            result = cpu_state_to_result(set_enabled.cpu_id);
            break;
        }
        case HB_DRIVER_PACKET_IOC_CONFIGURE_TRACE: {
            hb_driver_packet_configure_trace configure_trace;

            printk(TAGI "ioctl -- configure_trace\n");

            if (!(topa_page_order && topa_buffer_count)) {
                //Buffers must be configured before tracing can be configured
                result = -ENOSPC;
                goto OUT;
            }

            if (copy_from_user(&configure_trace, (void *) arg, sizeof configure_trace) != 0
                || !cpu_online(configure_trace.cpu_id)
                || configure_trace.pid == 0) {
                result = -EINVAL;
                goto OUT;
            }

            if (per_cpu(trace_state, configure_trace.cpu_id) == HB_DRIVER_TRACE_STATUS_TRACING) {
                //You can't reconfigure a CPU while it's tracing
                result = -EBUSY;
                goto OUT;
            }

            if ((result = configure_pt_on_cpu(configure_trace.cpu_id, &configure_trace))) {
                goto OUT;
            }

            //Check if we've allocated a ToPA for this CPU yet
            if (!per_cpu(topa_cpu, configure_trace.cpu_id)
                && (result = allocate_pt_buffer_on_cpu(configure_trace.cpu_id)) < 0) {
                goto OUT;
            }

            break;
        }

        case HB_DRIVER_PACKET_IOC_GET_TRACE_LENGTHS: {
            hb_driver_packet_get_trace_lengths get_lengths;
            uint64_t mask_msr;
            uint64_t buffer_index;
            uint64_t buffer_offset;
            uint64_t packet_byte_count;
            uint64_t buffer_size;

            printk(TAGI "ioctl -- get_trace_lengths\n");

            if (copy_from_user(&get_lengths, (void *) arg, sizeof get_lengths) != 0
                || !cpu_online(get_lengths.cpu_id)
                || !get_lengths.trace_buffer_length_out
                || !get_lengths.trace_packet_byte_count_out) {
                result = -EINVAL;
                goto OUT;
            }

            if ((result = preflight_trace_buffer_userspace_access(get_lengths.cpu_id)) < 0) {
                goto OUT;
            }

            if ((result = read_msr_on_cpu(get_lengths.cpu_id, MSR_IA32_RTIT_OUTPUT_MASK_PTRS, &mask_msr)) < 0) {
                goto OUT;
            }

            /*
             * This is from the Intel docs. ToPA provides very specific information about the last write location in
             * the output mask MSR. It's gross bit hacking but buffer_index tells us the index in our table (zero
             * index) and buffer_offset tells us the byte inside that buffer.
             */
            buffer_index = (mask_msr >> 7) & ((1LLU << 25) - 1);
            buffer_offset = (mask_msr >> 32) & ((1LLU << 32) - 1);
            packet_byte_count = buffer_index * (PAGE_SIZE << topa_page_order) + buffer_offset;

            buffer_size = get_topa_entry_count(get_lengths.cpu_id) * (PAGE_SIZE << topa_page_order);

            if (copy_to_user(get_lengths.trace_packet_byte_count_out, &packet_byte_count, sizeof packet_byte_count)
                || copy_to_user(get_lengths.trace_buffer_length_out, &buffer_size, sizeof buffer_size)) {
                result = -EIO;
                goto OUT;
            }

            result = 0;
            break;
        }
        default:
            result = -EINVAL;
            break;
    }

    OUT:
    //Unlock before we leave
    spin_unlock_irqrestore(&configuration_spinlock, flags);

    printk(TAGI "\tioctl result -> %ld\n", result);

    return result;
}

/**
 * Map the trace buffer for a given CPU to user space. This is only valid if the target CPU is not tracing.
 * Send the CPU index via the mmap offset field (you must multiply the ID by PAGE_SIZE lol)
 */
static int honey_driver_mmap(struct file *file, struct vm_area_struct *vma) {
    int result;
    unsigned int topa_entry_count;
    int i;
    uint64_t * topa;
    unsigned long len = vma->vm_end - vma->vm_start;
    int cpu = vma->vm_pgoff;
    unsigned long buffer_size = PAGE_SIZE << topa_page_order;
    unsigned long flags;

    //Take the configuration lock. All operations touch state and so we really need those to be serial.
    //A reader-writer lock could be used but that's honestly a bit more complicated than really necessary since we
    // don't really expect to have THAT many concurrent operations
    spin_lock_irqsave(&configuration_spinlock, flags);

    printk(TAGI "mmap call for CPU %d, size = %lu\n", cpu, len);

    if (!cpu_online(cpu)) {
        return -EINVAL;
    }

    if ((result = preflight_trace_buffer_userspace_access(cpu)) < 0) {
        goto EXIT;
    }

    topa_entry_count = get_topa_entry_count(cpu);

    if (len != topa_entry_count * buffer_size) {
        return -EINVAL;
    }

    topa = per_cpu(topa_cpu, cpu);
    for (i = 0; i < topa_entry_count; i++) {
        result = remap_pfn_range(vma,
                                 vma->vm_start + i * buffer_size,
                                 topa[i] >> PAGE_SHIFT,
                                 buffer_size,
                                 vma->vm_page_prot);
        if (result) {
            break;
        }
    }


    result = 0;
    EXIT:
    //Unlock before we leave
    spin_unlock_irqrestore(&configuration_spinlock, flags);

    return result;
}

static const struct file_operations honey_driver_fops = {
        .owner = THIS_MODULE,
        .unlocked_ioctl = honey_driver_ioctl,
        .mmap =    honey_driver_mmap,
        .llseek = no_llseek,
};

static struct miscdevice honey_driver_misc_dev = {
        .minor = MISC_DYNAMIC_MINOR,
        .name = "honey_driver",
        .fops = &honey_driver_fops,
        .mode = S_IRWXUGO,
};

static int honey_driver_init(void) {
    int result = 0;
    int cpu_count;
    int i;

    printk(TAGI "Starting...\n");

    //Preflight check to make sure we support PT (plus to store various required information)
    result = intel_pt_hardware_support_preflight();
    if (result < 0) {
        printk(TAGE "CPU does not support all required features, aborting...");
        goto ABORT;
    }

    //Register our devfs node
    result = misc_register(&honey_driver_misc_dev);
    if (result < 0) {
        printk(TAGE "Cannot register device\n");
        goto ABORT;
    }

    //XXX this doesn't actually work if you offline random cores in the middle (i.e. offline core 4 of 8) but
    // I'm choosing to ignore that because who offlines a CPU core while fuzzing??
    cpu_count = num_online_cpus();
    for (i = 0; i < cpu_count; i++) {
        per_cpu(trace_state, i) = HB_DRIVER_TRACE_STATUS_CORE_NOT_CONFIGURED;
    }

    printk(TAGI "Started!\n");
    return 0;

    ABORT:
    return result;
}

static void honey_driver_exit(void) {
    int i;
    int cpu_count;

    printk(TAGI "Unloading...\n");

    //XXX this doesn't actually work if you offline random cores in the middle (i.e. offline core 4 of 8) but
    // I'm choosing to ignore that because who offlines a CPU core while fuzzing??
    cpu_count = num_online_cpus();
    //Teardown all cpus
    for (i = 0; i < cpu_count; i++) {
        //This is safe since this is a NOP if the CPU has no buffers on it
        //If the CPU is tracing, the MSR clear will disable PT
        free_pt_buffer_on_cpu(i);
    }

    misc_deregister(&honey_driver_misc_dev);

    printk(TAGI "Unloaded!\n");
}

module_init(honey_driver_init);
module_exit(honey_driver_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Allison Husain");
