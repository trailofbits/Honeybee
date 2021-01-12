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
#include <time.h>
#include <stdbool.h>

#include "../honeybee_shared/hb_driver_packets.h"

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

bool honey_configure_get_trace_buffer_lengths(int driver_fd, uint16_t core, uint64_t *packet_byte_count,
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
    f0->start_address = 0x7ffff7f3a000;
    f0->stop_address = 0x7ffff7fce000; //canonical start address for shared libraries
//    f0->start_address = 0x0;
//    f0->stop_address = 0x7f0000000000; //canonical start address for shared libraries

    /* setup trace buffers */
    check_result(honey_configure_trace_buffers(fd, 50, 8));

//        const char *spawn_process = "/home/allison/Desktop/a.out";
    const char *spawn_process = "/home/allison/Downloads/HTMLFastParse/HTMLFastParseFuzzingCli/a.out";
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
//    sleep(2);
    uint64_t stop = current_clock();


    printf("trace time = %lu ns\n", stop - start);

    check_result(honey_set_capture_enabled(fd, target_cpu, 0x0));
    kill(pid, SIGKILL);

    uint64_t packet_byte_count = 0;
    uint64_t buffer_size = 0;
    check_result(honey_configure_get_trace_buffer_lengths(fd, target_cpu, &packet_byte_count, &buffer_size));
    printf("size = %lu, total allocation size = %lu\n", packet_byte_count, buffer_size);

    uint8_t *trace_buffer = mmap(NULL, buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                                 4096 * target_cpu /* offset */);
    if (trace_buffer == MAP_FAILED) {
        perror("Failed to mmap trace buffer!");
        abort();
    }

    if (packet_byte_count >= buffer_size) {
        //To force the stop codon in, we need to truncate the buffer...
        packet_byte_count = buffer_size - 1;
    }

    trace_buffer[packet_byte_count] = 0x55;

    FILE *f = fopen("/tmp/o.pt", "w+");
    fwrite(trace_buffer, packet_byte_count, 1, f);
    fclose(f);

    if (fd > 0) {
        close(fd);
    }
}