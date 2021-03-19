# Honeybee

Honeybee is a very fast Intel Processor Trace capture and decoding suite which enables previously unattainable performance in source and blackbox fuzzing alike by taking advantage of a custom ahead-of-time analysis cache to accelerate decoding multiple traces.

### Sub-projects

This repo contains a handful of sub-projects. A brief explanation of each is given below:

#### `honey_hive_generator`

This project is an executable which processes an ELF binary into the custom ahead-of-time cache (a "hive" file, typically ending with `.hive`). It is expected to be invoked once per binary being traced while the hive file it produces should be re-used for optimal performance.

#### `honey_driver`

This project is a Linux kernel module which implements a minimal, fuzzing optimized interface for configuring Intel Processor Trace. It creates a devfs mount at `/dev/honey_driver` and clients may communicate with the driver using `ioctl` and `mmap`. See `honeybee_shared/hb_driver_packets.h` for information about the supported `ioctl`s. Notable optimizations involve allowing each CPU's tracing to be managed independently and in kernel trace preparation. This is important in fuzzing workflows where many instances are parralized by pinning fuzzing processes to specific CPU cores. 

You do not need to communicate with the kernel module directly if you use the `honey_analyzer` library since it implements a full client using the `ha_capture_session_*` functions.

#### `honey_analyzer`
 
This project is a library (static by default or shared depending on build configuration) which implements everything an analysis tool needs to process traces given a hive file. It includes functions for interacting with the kernel module (`ha_capture_session_*`) and analyzing traces (`ha_analysis_session_*`).
 
#### `honey_coverage`

This is a demo project which uses `honey_analyzer` to gather both unique edge and basic block coverage using Intel PT for a given program. It outputs the following in a plain text format after the given program exits:

```
block set count
edge set count
[[block set elements (1 per line)]]
[[edge set elements  (1 per line)]]
```

#### `honey_tester`

This is project is a unit testing shim for `honey_analyzer`. It is used by `/unittest.py`. To run unit tests, download the [unit test data](https://github.com/trailofbits/Honeybee/releases/tag/0) and decompress it at the same level as this repository (i.e. adjacent) and then execute `python3 unittest.py`.


### Fuzzing implementations

As part of the initial Honeybee development cycle, we implemented support into [a fork of Honggfuzz](https://github.com/ezhes/honggfuzz/tree/honeybee). To build, follow build directions below. To fuzz a binary `${TARGET}`, use the following procedure:

1. Execute `${TARGET}$` under a debugger (ASLR should not be enabled) and determine the address range for the code you wish to trace. This can be done with lldb by launch the process and then executing `image dump sections`. In most cases where you are tracing the main binary of a program, this range is `0x1` to `0x6fffffffffff`. Call the starting and stop address `${START_ADDRESS}` and `${STOP_ADDRESS}` respectively.
2. Generate a hive for the target binary `${TARGET}` and store it at `${HIVE_PATH}`: `./honey_hive_generator "$TARGET" "${HIVE_PATH}"` 
3. Begin fuzzing. You may use whichever other arguments you wish, but Honeybee requires `--linux_honeybee_ipt_edge --honeybee_hive ${HIVE_PATH} --honeybee_start_address ${START_ADDRESS} --honeybee_stop_address ${STOP_ADDRESS}`

**Miscellaneous notes on fuzzing**

If you wish to persistently fuzz a program for maximal performance, you have two options. Firstly, if you have source, you can simply link in the honggfuzz persistent functions without adding software instrumentation by compiling with the flags `/honggfuzz/libhfuzz/libhfuzz.a /honggfuzz/libhfcommon/libhfcommon.a -ldl -lpthread -lrt`. If you do not have source but the target binary is relocatable, you can take advantage of the fact that relocatable ELF binaries are actually just shared libraries which you can load at runtime. You may use something like LIEF to expose a target function and then write a shim which loads the target binary at runtime and calls the target function through a persistent honggfuzz hook. Note that your `${START_ADDRESS}` and `${STOP_ADDRESS}` must be the address range at which the target binary (not the shim) is loaded to gather correct coverage information.

### Compiling

#### Dependencies

This project uses `cmake` for its primary build system. Honeybee also depends upon `libxed` for performing binary analysis in `honey_hive_generator` and `libipt` in `honey_test` for ensuring that Honeybee's decoder behaves identically to Intel's reference decoder. You can checkout and build all dependencies by executing `cd dependencies; ./build_dependencies.sh` 

### Honeybee user-space components

To build all of Honeybees user-space components, create a folder for the output products (`mkdir cmake-build-debug`) and then simply execute `cmake --build cmake-build-debug` This will build all targets to the `cmake-build-debug` folder.

### Honeybee kernel components

Building kernel components requires current kernel sources. Please refer to your distribution's manual for how to do this. Once sources are ready, the module may be compiled and loaded via `cd honey_driver; sudo make build_install` 

### Hongfuzz fork

1. Checkout the `honeybee` branch of [our fork](https://github.com/ezhes/honggfuzz/tree/honeybee) at the same level as the Honeybee repo.
2. Compile Honeybee's user-space components, ensuring that `libhoney_analyzer` builds to a static library.
3. Compile honggfuzz using `make`


### Contributors

* **Allison Husain** (University of California, Berkeley): Developed Honeybee's analysis algorithim, wrote Honeybee and of its tools
* **Artem Dinaburg** (Trail of Bits): Project mentor
* **Peter Goodman** (Trail of Bits): Project mentor
