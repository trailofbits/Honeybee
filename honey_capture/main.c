//
// Created by Allison Husain on 1/7/21.
//
#define _GNU_SOURCE

#include <stdlib.h>
#include <inttypes.h>
#include <linux/perf_event.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <wait.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>

#define _HF_PERF_MAP_SZ (1024 * 512)
#define _HF_PERF_AUX_SZ (1024 * 1024)
#define rmb() __asm__ __volatile__("" ::: "memory")

#define MSR_IA32_RTIT_CTL 0x00000570
#define MSR_IA32_RTIT_STATUS 0x00000571
#define MSR_IA32_RTIT_ADDR0_A 0x00000580
#define MSR_IA32_RTIT_ADDR0_B 0x00000581
#define MSR_IA32_RTIT_ADDR1_A 0x00000582
#define MSR_IA32_RTIT_ADDR1_B 0x00000583
#define MSR_IA32_RTIT_ADDR2_A 0x00000584
#define MSR_IA32_RTIT_ADDR2_B 0x00000585
#define MSR_IA32_RTIT_ADDR3_A 0x00000586
#define MSR_IA32_RTIT_ADDR3_B 0x00000587
#define MSR_IA32_RTIT_CR3_MATCH 0x00000572
#define MSR_IA32_RTIT_OUTPUT_BASE 0x00000560
#define MSR_IA32_RTIT_OUTPUT_MASK 0x00000561
#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

#define RTIT_CTL_TRACEEN           BIT(0)
#define RTIT_CTL_CYCLEACC          BIT(1)
#define RTIT_CTL_OS                BIT(2)
#define RTIT_CTL_USR               BIT(3)
#define RTIT_CTL_PWR_EVT_EN        BIT(4)
#define RTIT_CTL_FUP_ON_PTW        BIT(5)
#define RTIT_CTL_CR3EN             BIT(7)
#define RTIT_CTL_TOPA              BIT(8)
#define RTIT_CTL_MTC_EN            BIT(9)
#define RTIT_CTL_TSC_EN            BIT(10)
#define RTIT_CTL_DISRETC           BIT(11)
#define RTIT_CTL_PTW_EN            BIT(12)
#define RTIT_CTL_BRANCH_EN         BIT(13)
#define RTIT_CTL_MTC_RANGE_OFFSET  14
#define RTIT_CTL_MTC_RANGE         (0x0full << RTIT_CTL_MTC_RANGE_OFFSET)
#define RTIT_CTL_CYC_THRESH_OFFSET 19
#define RTIT_CTL_CYC_THRESH        (0x0full << RTIT_CTL_CYC_THRESH_OFFSET)
#define RTIT_CTL_PSB_FREQ_OFFSET   24
#define RTIT_CTL_PSB_FREQ          (0x0full << RTIT_CTL_PSB_FREQ_OFFSET)
#define RTIT_CTL_ADDR0_OFFSET      32
#define RTIT_CTL_ADDR0             (0x0full << RTIT_CTL_ADDR0_OFFSET)
#define RTIT_CTL_ADDR1_OFFSET      36
#define RTIT_CTL_ADDR1             (0x0full << RTIT_CTL_ADDR1_OFFSET)
#define RTIT_CTL_ADDR2_OFFSET      40
#define RTIT_CTL_ADDR2             (0x0full << RTIT_CTL_ADDR2_OFFSET)
#define RTIT_CTL_ADDR3_OFFSET      44
#define RTIT_CTL_ADDR3             (0x0full << RTIT_CTL_ADDR3_OFFSET)
#define RTIT_STATUS_FILTEREN       BIT(0)
#define RTIT_STATUS_CONTEXTEN      BIT(1)
#define RTIT_STATUS_TRIGGEREN      BIT(2)
#define RTIT_STATUS_BUFFOVF        BIT(3)
#define RTIT_STATUS_ERROR          BIT(4)
#define RTIT_STATUS_STOPPED        BIT(5)

#include <time.h>

long current_clock() {
    struct timespec tv;
    clock_gettime(CLOCK_MONOTONIC_RAW, &tv);

    return tv.tv_sec * 1e9 + tv.tv_nsec;
}

static size_t get_file_filter_size(const char *filename) {
    struct stat statbuf;
    if (stat(filename, &statbuf)) {
        abort();
    }

    return statbuf.st_size;
}

pid_t spawn_suspended(const char *path, char *const *argv) {
    pid_t pid = fork();
    // https://knight.sc/malware/2019/01/06/creating-suspended-processes.html
    if (pid == 0) {
        /* child */
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        //Since we do not use PTRACE_O_TRACEEXEC, this will trigger a SIGTRAP on success
        execv(path, argv);
    } else {
        /* parent */
        int status;
        waitpid(pid, &status, 0);
    }

    return pid;
}

void suspend_process(pid_t pid) {
    ptrace(PTRACE_INTERRUPT, pid, (caddr_t) 1, 0);
}

void unsuspended_process(pid_t pid) {
    ptrace(PTRACE_CONT, pid, (caddr_t) 1, 0);
}

void pin_process_to_cpu(pid_t pid, int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if (sched_setaffinity(pid, sizeof mask, &mask)) {
        perror("Couldn't pin to CPU");
    }

}

#include <stdbool.h>
#include "../honeybee_shared/hb_driver_packets.h"

bool honey_set_capture_enabled(int driver_fd, uint16_t core, bool enabled) {
    hb_driver_packet_set_enabled set_enabled;
    bzero(&set_enabled, sizeof set_enabled);

    set_enabled.cpu_id = core;
    set_enabled.enabled = enabled ? 1 : 0;

    int result = ioctl(driver_fd, HB_DRIVER_PACKET_IOC_SET_ENABLED, &set_enabled);
    if (result < 0) {
        perror("ioctl SET_ENABLED failed");
        return false;
    }

    return true;
}

bool honey_configure_trace_buffers(int driver_fd, uint32_t buffer_count, uint8_t page_power) {
    hb_driver_packet_configure_buffers configure_buffers;
    bzero(&configure_buffers, sizeof configure_buffers);

    configure_buffers.count = buffer_count;
    configure_buffers.page_count_power = page_power;

    int result = ioctl(driver_fd, HB_DRIVER_PACKET_IOC_CONFIGURE_BUFFERS, &configure_buffers);
    if (result < 0) {
        perror("ioctl CONFIGURE_BUFFERS failed");
        return false;
    }

    return true;
}

bool honey_configure_tracing(int driver_fd, uint16_t core, pid_t pid,
                             hb_driver_packet_range_filter filters[HB_DRIVER_PACKET_CONFIGURE_TRACE_FILTER_COUNT]) {
    hb_driver_packet_configure_trace configure_trace;
    bzero(&configure_trace, sizeof configure_trace);

    configure_trace.cpu_id = core;
    memcpy(configure_trace.filters, filters,
           HB_DRIVER_PACKET_CONFIGURE_TRACE_FILTER_COUNT * sizeof(hb_driver_packet_range_filter));
    configure_trace.pid = pid;

    int result = ioctl(driver_fd, HB_DRIVER_PACKET_IOC_CONFIGURE_TRACE, &configure_trace);
    if (result < 0) {
        perror("ioctl CONFIGURE_TRACE failed");
        return false;
    }

    return true;
}

bool honey_configure_get_trace_buffer_lengths(int driver_fd, uint16_t core, uint16_t *packet_byte_count,
                                              uint64_t *buffer_size) {
    hb_driver_packet_get_trace_lengths get_trace_lengths;
    bzero(&get_trace_lengths, sizeof get_trace_lengths);

    get_trace_lengths.cpu_id = core;
    get_trace_lengths.trace_packet_byte_count_out = packet_byte_count;
    get_trace_lengths.trace_buffer_length_out = buffer_size;

    int result = ioctl(driver_fd, HB_DRIVER_PACKET_IOC_GET_TRACE_LENGTHS, &get_trace_lengths);
    if (result < 0) {
        perror("ioctl GET_TRACE_LENGTH failed");
        return false;
    }

    return true;
}

static inline void check_result(bool result) {
    if (!result) {
        exit(1);
//        abort();
    }
}

static bool find_stream_end(uint8_t *buffer, uint16_t trace_length, uint64_t buffer_length,
                            uint64_t *stream_end_bytes_out) {
    uint64_t found_target = UINT64_MAX;

    for (uint64_t i = 0; i < buffer_length; i += (1 << 16) /* size of the trace length field */) {
        printf("value = %x\n", buffer[i]);
        if (buffer[i] == 0x55 /* stop codon */) {
            //We found a stop codon/canary. This is NEVER emitted by PT.
            //This indicates that PT never wrote to this page.
            found_target = i;
            break;
        }
    }

    if (found_target == UINT64_MAX) {
        //We didn't find ANY canaries, this means we overflowed. We can really only assume that the whole buffer is
        // valid. This will likely generate errors of some sort
        *stream_end_bytes_out = buffer_length - 1 /* space for the codon */;
        return true;
    }

    if (found_target == 0x00) {
        if (trace_length == 0x00) {
            *stream_end_bytes_out = 0;
            return true;
        } else {
            //Something went really wrong if we somehow expected data but found nothing
            printf("Expected data but found stop codon in first slot?\n");
            return false;
        }
    }

    //We now know we're within 1<<16 bytes so we can use our trace_length
    *stream_end_bytes_out = found_target - (1 << 16) + trace_length;
    return true;
}

static void reset_buffer(uint8_t *buffer, uint64_t trace_real_length) {
    /*
     * Concept: zeroing everything is expensive. We can lazily ""zero"" by erasing every n * (1<<16) bytes to ensure
     * that we can correctly determine where the last byte of the trace stream is by stepping till we hit a zero'd
     * page and then stepping backwards.
     *
     * We already do this in the kernel function allocate_pt_buffer_on_cpu, however we need to restore it each time.
     */

    //We need to restore all canaries before where the trace ends because presumably our trace stomped on them.
    for (uint64_t i = 0; i < trace_real_length; i += 1 << 16) {
        buffer[i] = 0x55;
    }
}

int main(int argc, const char *argv[]) {
    int fd = open("/dev/honey_driver", O_CLOEXEC | O_RDWR);
    if (fd < 0) {
        perror("Could not open driver");
        return 1;
    }

    int target_cpu = 7;

    hb_driver_packet_range_filter filters[HB_DRIVER_PACKET_CONFIGURE_TRACE_FILTER_COUNT];
    bzero(&filters, sizeof filters);
    hb_driver_packet_range_filter *f0 = &filters[0];
    f0->enabled = 0x1;
    f0->start_address = 0x0;
    f0->stop_address = 0x7f0000000000; //canonical start address for shared libraries

    /* setup trace buffers */
    check_result(honey_configure_trace_buffers(fd, 50, 8));

//    const char *spawn_process = "/home/allison/Downloads/HTMLFastParse/HTMLFastParseFuzzingCli/a.out";
    const char *spawn_process = "/home/allison/Desktop/a.out";
    pid_t pid = spawn_suspended(spawn_process, (char *const *) argv);
    pin_process_to_cpu(pid, target_cpu);
    printf("Spawned suspended proc %d\n", pid);

    /* setup tracing */
    check_result(honey_configure_tracing(fd, target_cpu, pid, filters));
    check_result(honey_set_capture_enabled(fd, target_cpu, 0x1));

    unsuspended_process(pid);

    uint64_t start = current_clock();
    int status;
    waitpid(pid, &status, 0);
//    sleep(1);
    uint64_t stop = current_clock();


    printf("trace time = %lu ns\n", stop - start);

    check_result(honey_set_capture_enabled(fd, target_cpu, 0x0));
    kill(pid, SIGKILL);

    uint16_t packet_byte_count;
    uint64_t buffer_size;
    check_result(honey_configure_get_trace_buffer_lengths(fd, target_cpu, &packet_byte_count, &buffer_size));
    printf("16-bit size = %d, total allocation size = %lu\n", packet_byte_count, buffer_size);

    uint8_t *trace_buffer = mmap(NULL, buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                                 4096 * target_cpu /* offset */);
    if (trace_buffer == MAP_FAILED) {
        perror("Failed to mmap trace buffer!");
        abort();
    }

    uint64_t true_byte_count;
    check_result(find_stream_end(trace_buffer, packet_byte_count, buffer_size, &true_byte_count));
    printf("True byte count = %lu\n", true_byte_count);
    trace_buffer[true_byte_count] = 0x55;

    FILE *f = fopen("/tmp/o.pt", "w+");
    fwrite(trace_buffer, buffer_size, 1, f);
    fclose(f);

//    reset_buffer(trace_buffer, true_byte_count);

    if (fd > 0) {
        close(fd);
    }
}