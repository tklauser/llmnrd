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

#ifndef IFACE_H
#define IFACE_H

#include <sys/socket.h>

size_t iface_addr_lookup(unsigned int ifindex, unsigned char family, 
			 struct sockaddr_storage *addrs, size_t addrs_size);

int iface_start_thread(void);
void iface_stop(void);

#endif /* IFACE_H */
