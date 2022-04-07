![perf-tools](https://lh5.googleusercontent.com/veTYa7eFG8uH_0wNU_oy_YgVcN9NcMDBidQ9XgANSw9lVDI_dSYhVg5aOlOH9chZEmEhInKrrd2AXKWxd852os74Z1YfonwoT1N2w-ZgvsYQLmvyA-b_N3ex5u6VwtL4eA=w1280)
# perf-tools
A collection of performance analysis tools, recipes, micro-benchmarks &amp; more

## Overview
* **do.py** -- A driver with handy shortcuts for setting up and doing profiling, over [Linux perf](https://perf.wiki.kernel.org/index).
* **kernels/** -- an evolving collection of x86 kernels
  * **gen-kernel.py** -- generator of X86 kernels
  * **jumpy.py** -- module for different jumping constructs
  * **peakXwide.c** -- sample kernels for a X-wide superscalar machine, e.g. 4 for Skylake
  * **sse2avx.c** -- another auto-generated kernel for SSE <-> AVX ISA transition penalty
  * **memcpy.c** -- a custom kernel for strings of libc demonstrating how to timestamp a region-of-interest
  * **fp-arith-mix.c** -- demonstrates utilization of extra counters in Icelake's PMU
  * **rfetch3m** -- a random fetcher across 3MB code footprint (auto-generated)
  * There are more kernels produced by **build.sh** though not uploaded to git
* **lbr.py** -- A module for processing Last Branch Record (LBR) streams
* **pmu.py** -- A module for interface to the Performance Monitoring Unit (PMU)
* **pmu-tools/** -- linked Andi Kleen's perf-based great tools
  * **toplev** -- profiler featuring the [Top-down Microarchitecture Analysis](http://bit.ly/tma-ispass14) (TMA) method on Intel processors
  * **ocperf** -- perf wrapper that converts Intel event names to perf-events syntax
### Checkout with: 
`git clone --recurse-submodules https://github.com/aayasin/perf-tools`


## Usage
### setting up system (for more robust profiling)
* to setup the perf tool, invoke `./do.py setup-perf`
* to turn-off SMT (CPU hyper-threading), invoke `./do.py disable-smt`; don't forget to re-enable it once done, e.g. `./do.py enable-smt`
* `./do.py disable-prefetches` to disable hardware prefetches. Ditto re-enable comment for this/next commands.
* `./do.py enable-fix-freq` to use fixed-frequency (in paritcular disables Turbo).
* `./do.py disable-atom` to disable efficient-cores in Hybrid processors.

### profiling
First, edit `run.sh` to invoke your application or use the `-a '<your app and its args>'`, alternatively.
* to profile, simply `./do.py profile` which includes multiple steps:
  * **logging** step: collects the system setup info
  * **basic counting & sampling** steps: collect key metrics like time or CPUs utilized,
    via basic profiling and output top CPU-time consuming commands/modules/functions as well as
    the source/disassembly for top function(s).
  * **topdown profiling** steps: collect reduced tree, auto drill-down and full-tree collections with multiple re-runs. 
  * **advanced sampling** steps: do more profiling using advanced capabilities of the PMU, and output certain reports 
    at the assembly level (of hottest command).
    Example reports include instruction-mixes, hitcounts (basic-block execution counts), paths to precise
    events and related-stats. Note some of these steps are disabled by default.

  A filtered output will be dumped on screen while all logs are saved to the current directory.  
  Use `--profile-mask 42`, as an example, to invoke subset of all steps,
    or `-N` to disable the step with re-runs.  
  For topdown profiling and advanced sampling, see [system requirements](#head3sys).
* `./do.py log` will only log hardware and software setup.
* `./do.py setup-perf profile` will do the setup and default profiling steps at once.
* `./do.py tar` will archive all logs into a shareable tar file.
* `./do.py all` will setup perf before doing all above profiling steps.
* `./do.py profile -pm 222 -v1` will do selected profile steps - *per-app counting, topdown 2-levels,
  sampling w/ PEBS* - and print underlying commands as well.

### kernels (microbenchmarks)
* to build pre-defined ones, simply `cd kernels/ && ./build.sh`, or
* `GEN=0 ./build.sh` from kernels/ dir to re-build the kernels without generating them
* to run a kernel, invoke it with number-of-iterations, e.g.
`    ./kernels/jumpy5p14 200000000`
* to create a custom kernel, set the desired parameters. e.g.
`    ./kernels/gen-kernel.py -i PAUSE -n 10`
  outputs a C-file of a loop with 10 PAUSE instructions, that can be fed to your favorite compiler.

### tools
A set of command-line tools to facilitate profiling
* **addrbits** -- extracts certain bit-range of hexa input
* **lbr_stats** -- calculates stats on LBR-based profile
* **ptage** -- computes percentages & sum of number-prefixed input

### wrappers
Shortcuts to set-up certain tools
* **build-perf.sh** -- builds the perf tool from scratch; invoke with `./do.py build-perf` to let it
    use the installer of your Linux distribution (Ubuntu is the default).
* **build-xed.sh** -- downloads & builds Intel's xed. Note xed usage is disabled by default;
    invoke with `./do.py setup-all --tune :xed:1`.

## More information
### <a name="head3sys">System requirements</a>
Required Linux kernel for most recent processors :tada:  
Intel product | Kernel version
------------- | --------------
Ice Lake | 5.10
Rocket Lake | 5.11
Alder Lake | 5.13

Besides, perf tool version 5.14 or newer is required. See `do.py --install-perf` for more.
