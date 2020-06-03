# Examples

This directory contains multiple working examples based on smart_sample, our test binary. Pre-compiled versions of smart_sample are provided in the *bin* directory. You can compile smart_sample yourself, but the thread tracking and indirect modes will most likely be broken as the current hooks have been tailored for the supplied binaries. You'll have to fix the hooks yourself if you want to take that route.

Smart_sample contains 3 "bugs" triggered by 4 payloads:

MAGICABRT: standard crash
MAGICAHNG: hang
MAGICOOL! and later MAGICOOPS: stateful crash

You can find the sources in the **smart_sample** directory

Note that most of the examples you will find here will require you to recompile afl-taenia in an appropriate mode. You can choose to compile in debug mode on top of that. Debug mode will provide MUCH more logs and a slowed down fuzzing, and is useful to better understand what is going on under the hood.

Note that if you compiled afl-taenia in debug mode (-d), you must use the *_debug* config files, otherwise use the *_standard* ones.

We encourage you to run the **get_log.sh** script in another terminal to get the logs real time while testing afl-taenia.

You can find the output provided by afl-taenia in the **output** directory of the example you decided to run.

## Configuration reference

the file configuration_reference contains all possible configuration keys and a small description of what it

## Basic

This directory contains basic configurations that will work with various compilation modes, namely:

- simple mode
- thread tracking

### Usage

#### Simple mode

In this mode, afl-taenia will fuzz in memory and will take all threads into account for its path discovery. The payload entry point is the **smart_broke** function.

./build.sh
./run.sh examples/basic/conf_basic_standard

Or in debug mode:

./build.sh -d
./run.sh examples/basic/conf_basic_debug

#### Thread tracking

In this mode, afl-taenia will fuzz in memory but will use the thread tracking feature to only take interesting threads into account for its path discovery. The payload entry point is the **smart_broke** function.

See **afl_taenia/qemu_mode/taenia/hooks.c** for details on the inter-thread communication API hooking. 

./build.sh -t
./run.sh examples/basic/conf_basic_standard

Or in debug mode:

./build.sh -t -d
./run.sh examples/basic/conf_basic_debug

## Thread filtering

In this exemple, we demonstrate the thread filtering mode (-m), where afl-taenia will only take its own fuzzing thread in consideration. This mode is usefull when you know the thread that is of interest will not communicate with other threads. The payload entry point is the **smart_parse** function.

### Usage

./build.sh -m
./run.sh examples/thread_filtering/conf_thread_filtering_standard

Or in debug mode:

./build.sh -m -d
./run.sh examples/thread_filtering/conf_thread_filtering_debug

## Stateful mode

In this exemple, we demonstrate the stateful mode. Afl-teania will fuzz in memory and with thread tracking, and will restart the fuzzing every 10000 payloads. When an interesting behaviour is observed, the 10000 payloads are saved. This is the only mode capable of providing both payloads for the stateful crash. Every other mode will only report the MAGICOOPS payload. The payload entry point is the **smart_broke** function.

### Usage

./build.sh -t
./run.sh examples/stateful_mode/conf_stateful_mode_standard

Or in debug mode:

./build.sh -t -d
./run.sh examples/stateful_mode/conf_stateful_mode_debug

## Indirect mode

In this exemple, we demontrate the indirect mode. Indirect mode works by replacing a function that supplies data in a buffer and that is called in a loop by the program. (A common exemple is a receive on a socket). We replace the function and use the output buffer to provide afl-taenia payloads to the program. Fuzzing speed is limited by the speed with which the program call our function. The payload entry point is the call to **recv** inside the **smart_broker_task** function.

### Usage

Note that as we are inserting ourselves in a network listeninig function, we need to initiate the fuzzing process by connecting once to the socket in order to pass the accept() and go to the recv loop that we exploit for our fuzzing. The script **bot_ping.sh** will help us by doing just that.

./build.sh -t -i
scripts/bot_ping.sh (in another terminal)
./run.sh examples/indirect_mode/conf_indirect_mode_standard

Or in debug mode:

./build.sh -t -i -d
scripts/bot_ping.sh (in another terminal)
./run.sh examples/indirect_mode/conf_indirect_mode_debug

## Replay simple

This example demonstrate the replay feature. It will replay a crash inducing payload in memory. It should trigger the abort bug.

### Usage

./build.sh (can be in any mode that is properly configured for fuzzing)
./replay_payload.sh examples/replay_simple/conf_replay_simple

## Replay stateful

This example demonstrate the stateful replay feature. It will replay an entire crash inducing payload archive in memory. It should trigger the stateful abort bug.

### Usage

./build.sh (can be in any mode that is properly configured for fuzzing)
./replay_payload.sh examples/replay_stateful/conf_replay_stateful