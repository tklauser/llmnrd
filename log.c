#include <stdarg.h>
#include <stdbool.h>

#include "log.h"

static bool use_syslog;

void log_lvl(int lvl, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	if (!use_syslog) {
		FILE *out = stderr;
		switch (lvl) {
		case LOG_ERR:
			fputs("Error: ", stderr);
			break;
		case LOG_WARNING:
			fputs("Warning: ", stderr);
			break;
		case LOG_INFO:
		case LOG_DEBUG:
			out = stdout;
			break;
		}
		vfprintf(out, fmt, ap);
	} else {
		vsyslog(lvl, fmt, ap);
	}

	va_end(ap);
}

void log_to_syslog(void)
{
	use_syslog = true;
}
