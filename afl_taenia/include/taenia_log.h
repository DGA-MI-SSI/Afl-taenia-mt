/*
 * taenia_log.h
 */

#ifndef AFL_TAENIA_TAENIA_LOG_H_
#define AFL_TAENIA_TAENIA_LOG_H_

#include <stdarg.h>

#include "taenia_config.h"

void log_common(const int color, const char *file, int line, const char *format, ...);
void raw_log(const char * str);

#define LOG_ERROR(format, ...) log_common(LOG_COLOR_ERROR, __FILE__, __LINE__, format, ##__VA_ARGS__)
#define LOG_INFO(format, ...) log_common(LOG_COLOR_INFO, __FILE__, __LINE__, format, ##__VA_ARGS__)

#ifdef DEBUG
#define LOG_DEBUG(format, ...) log_common(LOG_COLOR_DEBUG, __FILE__, __LINE__, format, ##__VA_ARGS__)
#define RAW_DEBUG(format, ...) log_common(LOG_COLOR_RAW_DEBUG, "", 0, format, ##__VA_ARGS__)
#else
#define LOG_DEBUG(format, ...)
#define RAW_DEBUG(format, ...)
#endif

#ifdef TAENIA_DEBUG_PATH
void log_path(const char *format, ...);
#define LOG_PATH(format, ...) log_path(format, ##__VA_ARGS__)
#else
#define LOG_PATH(format, ...)
#endif

#endif /* AFL_TAENIA_TAENIA_LOG_H_ */
