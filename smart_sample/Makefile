
PROGNAME    = smart_sample
VERSION     = 0.1

PROGS		= smart_sample libsample.so

CFLAGS     += -Wall -Wextra -Wconversion -Wstrict-overflow
CFLAGS     += -I../afl_taenia/include

LDFLAGS    ?= -lpthread -lrt 

all: proc_smart_sample smart_sample

smart_sample: smart_sample.c smart_sample.h ../afl_taenia/src/taenia_log.c ../afl_taenia/include/taenia_log.h
	$(CC) $(CFLAGS) $(OFLAGS) $^ -o smart_sample $(LDFLAGS)

smart_sample_lib: smart_sample_lib.c smart_sample_lib.h ../afl_taenia/src/taenia_log.c ../afl_taenia/include/taenia_log.h
	$(CC) $(CFLAGS) $(OFLAGS) -fPIC -shared -fno-inline $^ -o libsample.so $(LDFLAGS)

proc_smart_sample: proc_smart_sample.c proc_smart_sample.h ../afl_taenia/src/taenia_log.c ../afl_taenia/include/taenia_log.h
	$(CC) $(CFLAGS) $(OFLAGS) $^ -o proc_smart_sample $(LDFLAGS)

clean:
	rm -f *.o
	rm -f $(PROGS)

#mrproper: clean
#	rm -f $(PROGS)
