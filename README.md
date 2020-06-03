# AFL-TAENIA-MT

## Introduction

afl-taenia-mt lets the user fuzz in-memory a given function in a binary with afl while not being overly confused with threads.

## Architecture

```
+-----+                                        +-----------+
| afl |                                        |  target   |
|     |                               +--------+           |
|     + --> /dev/shm/afl_input -----> + afl-taenia-mt -> dstFunc  |
|     |                               +                    |
|     |                               +-----+--+           |
|     |                                     |  |           |
|     |             +-----taenia_shm.01-----+  |           |
|     |             |                          |           |
|     |          +--+----------+               |           |
|     | <-pipe-> + fork_server |               |           |
|     |          +-------------+               |           |
|     |                                        +-----------+
|     + <-- maybe_log() sh_mem(SHM_ENV_VAR)<-- +   qemu    |
+-----+                                        +-----------+
```

**Run order:**

* afl starts,
* afl runs the target binary on a patched qemu user mode,
* qemu triggers a snippet of code that starts the forkserver,
* the forkserver forks, the parent / fork_server waits while the child resumes the execution of target,
* target loads (via LD_PRELOAD) the library libtaenia that hooks an imported function (currently pthread_create) and creates a thread to execute the targeted function directly,
* afl provides a new input to libtaenia through the shared memory afl_input,
* libtaenia executes the targeted function with this input, waits for it to end/timeout/crash, then notify afl,
* qemu computes coverage on each basic block transitions with calls to maybe_log(), which updates the trace_bits table of afl,
* the parent reruns the child if afl-taenia-mt detects an error.

## Scripts

Several scripts are provided :

* install_package.sh: install the required packages
* build.sh : build the whole solution, several options are available:

  * -a: arch, x86 or x86_64.
  * -d: build in debug mode.
  * -g: prepare qemu for gdb.
  * -h: help.
  * -i: indirect mode, the target takes its input from the fuzzer instead of the fuzzer providing its inputs directly (useful to fuzz after standard function like recvfrom, memcpy...). For smart_sample, you'll need to make the first connection (nc 127.0.0.1 8080) to initiate fuzzing in indirect mode.
  * -l: enable macroscopic thread logs.
  * -m: thread filtering mode: only follow libtaenia's thread.
  * -o: do not compile qemu.
  * -p: enable the debug path logs.
  * -s mode: define complexity mode for smart_sample, mode can be: SIMPLE, SIMPLER, SIMPLEST.
  * -t: use thread-tracking.

* run.sh: run afl, needs a configuration file as argument (see the configuration example in smart_sample/taenia_configuration). If you add the word 'continue' after the configuration file, afl-taenia-mt will continue the previous execution instead of starting over, thus keeping all input files he has already found.
* replay_payload.sh: replay a payload or a serie of payloads, needs a configuration as argument (see the configuration exemple in the exemples folder).
* scripts/get_log.sh: print the logs real time.
* scripts/display_inputs.sh: display the inputs found by afl-taenia-mt.
* scripts/track_paths.py: parse the logs afl-taenia-mt output in debug path mode and produce dot graphs of what has been executed by all queued inputs, several options are available:

  * -a: arch, x86 or x64.
  * -c: continuous mode, track_path parses and wipes the log file every 10s.
  * -d: dumb mode, track all pathes even those that are not saved by afl.
  * -f: target binary file, the script will try to get symbols from it.
  * -g: graph, output svg graphs.
  * -i: ida, output json for ida_color_paths.py.
  * -l: file containing afl-taenia-mt DEBUG_PATH logs.
  * -o: offset, to set the process global memory offset.
  * -t: do not display threads, for cleaner graphs.

* scripts/ida_color_paths.py: colorize the code blocks, line and functions executed by afl-taenia-mt in ida (blue for executed, green for new, orange if caused a hang and red if caused a crash), several functions are available:

  * parse_path_info(file_path): parse the file exported by track_paths.py.
  * list_threads(data): list all threads executed.
  * color_thread(data, thread_id): color the path of a given thread.
  * color_path(data, path_id): color a given path (also called input in afl).
  * color_meta_path(data): color the meta_path made of the union of all paths.

## Exemples

Working configuration for much of the modes described below are provided in the **exemples** directory. See exemples/README.md for more details.

## Main modes

afl-taenia-mt offers three different main modes:

* simple mode (default)
* thread filtering mode
* thread tracking mode

### Simple mode

The simple mode lets you use standard afl++ fuzzing but in-memory. It serves as a basis for the two other modes.
To use it, simply compile the whole project (using the build.sh), and adapt the configuration file to your case.

This mode rely on LD_PRELOAD hooking to inject and run the libteania library. The initial hooked function is pthread_create. This can be changed at the expense of a little source modification by the user in afl_taenia/qemu_mode/taenia/taenia.c.

### Thread filtering mode

The thread filetring mode is much like the simple mode, except afl-taenia-mt will only follow libtaenia's fuzzing thread for its new code path discovery, thus filtering all the other running threads. This is suitable when you want to fuzz a single function that does not communicate with other threads.

Thread filtering mode can be enabled with the -m build option.

### Thread tracking mode

The thread tracking mode is more advanced. Starting from an entry function and given send() and recv() functions used to exchange data between threads, it will track all threads implied. Such threads are, of course the thread executing the entry function, but also all threads calling a tracked recv() functions on an input sent (through a tracked send() function) by an already tracked thread.

Unfortunately, this mode rely on inline hooking and so requires the user to write himself the send() and recv() hook. The code impacted is in afl_taenia/qemu_mode/taenia/hooks.c.

Thread tracking mode can be enabled with the -t build option.

## Secondary modes

afl-taenia-mt offers two different secondary modes:

* Stateless mode (default)
* Statefull mode

### Stateless mode

The stateless mode assumes that the fuzzed function is stateless, meaning that it doesn't change the global program behaviour.
In this mode, afl-taenia-mt will send payloads to the function without ever restarting the program until it crashes or timeouts. If the function is indeed stateless, the last payload will be responsible for the crash or timeout, thus, the last payload is the only thing that is logged by AFL.

### Statefull mode

The statefull mode tries to provide flexibility while fuzzing a statefull function. It allows the user to provide an iteration number "X" that afl-taenia-mt will use as a hard limit before restarting the program. A set of "X" payload is called a **run**. afl-taenia-mt will restart the target binary after every run.
While fuzzing in statefull mode, afl-taenia-mt will save every payload of the current run in an archive. If the run ends without a crash or a hang, this archive is discarded. Otherwise, the archive is saved, in order to allow the user to replay the entire run and identify the subset of payload that led to the crash/hang.

## Input provision mode

afl-taenia-mt offers two way to provide input to a target:

* Standard mode
* Indirect mode

### Standard mode

afl-taenia-mt simply calls the targeted function with a buffer containing the provided input. This is exactly the same as afl++, but from memory.

### Indirect mode

afl-taenia-mt saves its input in a buffer. When the targeted function is called in the normal program execution flow, afl-taenia-mt will force its input onto the function, usually as its return value. A suitable targeted function for this mode could be a recv(), as its return value will most likely be used in the rest of the program.

For this mode to work, we need to hook the function in order to replace the standard recv() that takes its input from the network, with our recv() that takes its input from afl's buffer.

Beware of the following facts:

* The targeted function must be inside a while loop, or else the fuzzing will stop quickly. It is often true for recv().
* The targeted loop (containing the targeted function) must be entered. For recv(), it means that the required listen(), bind() and accept() have been passed successfully. So you need to initiate a first connection (netcat and an empty payload are fine as we overwrite recv()). Another way to go is to overwrite all these functions so they are all ok.
* When a crash is found, afl-taenia-mt will restart the target, the previous property must remain true. For recv(), it may be problematic because bind() can be unhappy to reuse a port previously used. You can overwrite bind to avoid that problem.
* Afl does not like to be asked for a new input when he has not finished dealing with one. This leads afl to not answer properly when taenia_qemu pings him. The best way to avoid this problem is to use thread_tracking to make sure everything has been dealt with.

See the example in hooks.c for more details on how we did it.

## New features

### Libraries tracking

Originally, afl does not track the code inside the shared libs used by the target binary. afl-taenia-mt adds a feature allowing the user to provide a whitelist of shared libs to be tracked. This is usefull in the case of custom shared libs that can be equally interesting as the target binary itself.
This tracking can be enabled with the **afl_tracked_libs** key in the configuration file, where the user must provide a comma separated list of shared libs.

When the user starts fuzzing, afl-taenia-mt prints the list of shared libs used by the target program in the logs. The user is advised to tap directly into this list to populate the configuration file.

Using this feature, shared libraries are effectively viewed as part of the target binary by afl-taenia-mt.

### Process tracking

This feature only makes sense in the context of the stateful mode. It allows the user to specify a whitelist of process names, that will be monitored for crash by afl-taenia-mt at the end of a stateful run. The goal is to highligth inter process communication induced crash.

Crash detection work as follows:

1. Starts a new stateful run
2. Takes a snapshot of the whitelisted processes
3. Do the run
4. Takes a snapshot of the whitelisted processes
5. Compare the two snapshots.
    * No differences -> discard the run
    * Differences -> log the run and the processes that crashed
6. Handle the case
    * Stop fuzzing on crash if configured to
    * Continue fuzzing as if nothing happend on crash if configured to
    * if no crash, continue fuzzing

This feature comes with limitations. Namely:

* We have no control over the processes that we monitor. In stateful mode, the target binary is restarted after each run. At the moment, we have no way of controling the other binaries from AFL. In short, we can't prevent stateful modification to build until crash, creating false positives. A very less then perfect solution would be to save pretty much all payloads. Meh.
* It is hard to be sure that a crash was induced by the current stateful run, as it may have been induced by some previous run, and the crash was delayed by some mechanism, being detected only at the end of the current run.
