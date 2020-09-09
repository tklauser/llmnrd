/*
 * Copyright (C) 2015 Tobias Klauser <tklauser@distanz.ch>
 *
 * This file is part of llmnrd.
 *
 * llmnrd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 * llmnrd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with llmnrd.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <syslog.h>

#include "compiler.h"

void log_lvl(int lvl, const char *fmt, ...) __check_format_printf(2, 3);

void log_to_syslog(void);

#define log_err(fmt, args...)	log_lvl(LOG_ERR, fmt, ##args)
#define log_warn(fmt, args...)	log_lvl(LOG_WARNING, fmt, ##args)
#define log_info(fmt, args...)	log_lvl(LOG_INFO, fmt, ##args)
#ifdef DEBUG
# define log_dbg(fmt, args...)	log_lvl(LOG_DEBUG, fmt, ##args)
#else
# define log_dbg(fmt, args...)
#endif

#endif /* LOG_H */
