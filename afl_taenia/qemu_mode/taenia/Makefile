PROGNAME    = libtaenia
VERSION     = 0.1

PROGS       = libtaenia.so

CFLAGS     += -fPIC -shared -fno-inline
CFLAGS     += -Wall -Wextra -Wconversion -Wstrict-overflow -I ../../include

LDFLAGS     = -lpthread -ldl -lrt 

all: libtaenia

libtaenia: taenia.c thread_tracking.c lib_tracking.c elf_hook.c shm.c ../../src/taenia_log.c hooks.c
	$(CC) $(CFLAGS) $^ -o libtaenia.so $(LDFLAGS)

clean:
	rm -f *.o
	rm -f $(PROGS)
