/*
 * taenia_log.c
 * @brief: log functionalities.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#include "taenia_log.h"

static long int gettid() {
	return syscall(SYS_gettid);
}

void raw_log(const char *str) {
    char buf[LOG_SIZE];
    snprintf(buf, LOG_SIZE, "%s\n", str);

    int fd = 0;
    if ((fd = open("/dev/shm/afl_debug", O_RDWR | O_APPEND | O_CREAT, S_IRWXU)) != 0)
    {
        if(write(fd, buf, strlen(buf)) == 0) {
            printf("[error|libtaenia] Cannot write log '%s', error: %s (%d).\n", str, strerror(errno), errno);
            exit(0);
        }
        if (close(fd) < 0)
        {
            printf("[error|libtaenia] Cannot close, error: %s (%d).\n", strerror(errno), errno);
            exit(0);
        }
    }
    else
    {
        printf("[error|libtaenia] Cannot open log file to write '%s', error: %s (%d).\n", str, strerror(errno), errno);
    }
}

void log_common(const int color, const char *file, int line, const char *format, ...) {
    char str[LOG_SIZE] = {0};
    char buf[LOG_SIZE] = {0};
    struct timeval tv_now;
    va_list arg;

    gettimeofday(&tv_now, NULL);

    va_start(arg, format);
    vsnprintf(str, LOG_SIZE, format, arg);
    va_end(arg);

    snprintf(buf, LOG_SIZE, "\033[01;%dm[%d:%ld|%s:%d|%06ld.%06ld] %s\033[00m",
            color,
            getpid(), gettid(),
            file, line,
            (long int)tv_now.tv_sec % 10000000, (long int)tv_now.tv_usec,
            str);
    raw_log(buf);
}

#ifdef TAENIA_DEBUG_PATH
pthread_mutex_t debug_path_log_mutex = PTHREAD_MUTEX_INITIALIZER;
void log_path(const char *format, ...)
{
    char str[LOG_SIZE] = {0};
    char buf[LOG_SIZE] = {0};
    va_list arg;
    va_start(arg, format);
    vsnprintf(str, LOG_SIZE, format, arg);
    va_end(arg);

    int fd = 0;
    pthread_mutex_lock(&debug_path_log_mutex);
    if ((fd = open("/dev/shm/afl_debug_path", O_RDWR | O_APPEND | O_CREAT, S_IRWXU)) != 0)
    {
        snprintf(buf, LOG_SIZE, "%ld|%s\n", gettid(), str);
        if(write(fd, buf, strlen(buf)) == 0) {
            LOG_ERROR("log_path write error.");
        }
        if (close(fd) < 0)
        {
            printf("[error|taenia-qu] Cannot close afl_debug_path while writing %s, error: %s (%d).\n", str, strerror(errno), errno);
        }
    }
    else
    {
        printf("[error|taenia-qu] Cannot open afl_debug_path to write '%s', error: %s (%d).\n", str, strerror(errno), errno);
    }
    pthread_mutex_unlock(&debug_path_log_mutex);
}
#endif

