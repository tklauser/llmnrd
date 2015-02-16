/*
 * Copyright (C) 2014-2015 Tobias Klauser <tklauser@distanz.ch>
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "llmnr-packet.h"
#include "log.h"
#include "socket.h"

static const int YES = 1;
static const int NO = 0;

int socket_open_v4(uint16_t port)
{
	int sock;
	struct sockaddr_in sa;
	struct ip_mreq mreq;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		log_err("Failed to open UDP socket: %s\n", strerror(errno));
		return -1;
	}

	/* pass pktinfo struct on received packets */
	if (setsockopt(sock, IPPROTO_IP, IP_PKTINFO, &YES, sizeof(YES)) < 0) {
		log_err("Failed to set IP_PKTINFO option: %s\n", strerror(errno));
		goto err;
	}

	/* bind the socket */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		log_err("Failed to bind() socket: %s\n", strerror(errno));
		goto err;
	}

	/* join the multicast group */
	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr.s_addr = inet_addr(LLMNR_IPV4_MCAST_ADDR);
	mreq.imr_interface.s_addr = INADDR_ANY;

	if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		log_err("Failed to join multicast group: %s\n", strerror(errno));
		goto err;
	}

	/* disable multicast loopback */
	if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, &NO, sizeof(NO)) < 0) {
		log_err("Failed to disable multicast loopback: %s\n", strerror(errno));
		goto err;
	}

	return sock;
err:
	close(sock);
	return -1;
}

int socket_open_rtnl(void)
{
	int sock;
	struct sockaddr_nl sa;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		log_err("Failed to open netlink route socket: %s\n", strerror(errno));
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	/*
	 * listen for following events:
	 * - network interface create/delete/up/down
	 * - IPv4 address add/delete
	 * - IPv6 address add/delete
	 */
	sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		log_err("Failed to bind() netlink socket: %s\n", strerror(errno));
		goto err;
	}

	return sock;
err:
	close(sock);
	return -1;
}
