/*
 * Simple LLMNR (RFC 4795) query tool.
 *
 * Copyright (C) 2015-2017 Tobias Klauser <tklauser@distanz.ch>
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

#define _GNU_SOURCE
#define __APPLE_USE_RFC_3542
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "compiler.h"
#include "llmnr-packet.h"
#include "log.h"
#include "pkt.h"

static const char *short_ops = "c:d:i:I:t:T:6hV";
static const struct option long_opts[] = {
	{ "count",	required_argument,	NULL, 'c' },
	{ "id",		required_argument,	NULL, 'd' },
	{ "interval",	required_argument,	NULL, 'i' },
	{ "interface", 	required_argument,	NULL, 'I' },
	{ "timeout",	required_argument,	NULL, 't' },
	{ "type",	required_argument,	NULL, 'T' },
	{ "ipv6",	no_argument,		NULL, '6' },
	{ "help",	no_argument,		NULL, 'h' },
	{ "version",	no_argument,		NULL, 'V' },
	{ NULL,		0,			NULL, 0 },
};

static void __noreturn usage_and_exit(int status)
{
	fprintf(stdout, "Usage: llmnr-query [OPTIONS...] NAME\n"
			"Options:\n"
			"  -c, --count NUM       number of queries to send (default: 1)\n"
			"  -d, --id NUM          set LLMNR transaction id (default: 0)\n"
			"  -i, --interval NUM    interval between queries in ms (default: 500)\n"
			"  -I, --interface NAME  send multicast over specified interface\n"
			"  -t, --timeout NUM     time to wait for reply in ms (default: 1000)\n"
			"  -T, --type TYPE       set query type; must be one of A, AAAA, ANY (default: ANY)\n"
			"  -6, --ipv6            send queries over IPv6\n"
			"  -h, --help            show this help and exit\n"
			"  -V, --version         show version information and exit\n");
	exit(status);
}

static void __noreturn version_and_exit(void)
{
	fprintf(stdout, "llmnr-query %s %s\n"
			"Copyright (C) 2015-2017 Tobias Klauser <tklauser@distanz.ch>\n"
			"Licensed under the GNU General Public License, version 2\n",
			VERSION_STRING, GIT_VERSION);
	exit(EXIT_SUCCESS);
}

static const char *query_type(uint16_t qtype)
{
	switch (qtype) {
	case LLMNR_QTYPE_A:
		return "A";
	case LLMNR_QTYPE_AAAA:
		return "AAAA";
	case LLMNR_QTYPE_ANY:
		return "ANY";
	default:
		return "<unknown>";
	}
}

int main(int argc, char **argv)
{
	int c, sock;
	const char *query_name, *iface = NULL;
	size_t query_name_len;
	unsigned long i, id = 0, count = 1, interval_ms = 500, timeout_ms = 1000;
	uint16_t qtype = LLMNR_QTYPE_ANY;
	bool ipv6 = false;
	struct pkt *p;
	unsigned int ifindex = 0;
	static const int TTL = 255;

	while ((c = getopt_long(argc, argv, short_ops, long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			count = strtoul(optarg, NULL, 0);
			break;
		case 'd':
			id = strtoul(optarg, NULL, 0);
			break;
		case 'i':
			interval_ms = strtoul(optarg, NULL, 0);
			break;
		case 'I':
			iface = xstrdup(optarg);
			break;
		case 't':
			timeout_ms = strtoul(optarg, NULL, 0);
			break;
		case 'T':
			if (xstreq("A", optarg))
				qtype = LLMNR_QTYPE_A;
			else if (xstreq("AAAA", optarg))
				qtype = LLMNR_QTYPE_AAAA;
			else if (xstreq("ANY", optarg))
				qtype = LLMNR_QTYPE_ANY;
			else {
				printf("Invalid query type: %s\n", optarg);
				usage_and_exit(EXIT_FAILURE);
			}
			break;
		case '6':
			ipv6 = true;
			break;
		case 'V':
			version_and_exit();
		case 'h':
			usage_and_exit(EXIT_SUCCESS);
		default:
			usage_and_exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc)
		usage_and_exit(EXIT_FAILURE);

	query_name = argv[optind];
	query_name_len = strlen(query_name);
	if (query_name_len > UINT8_MAX) {
		log_err("Query name too long\n");
		return -1;
	}

	sock = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		log_err("Failed to open UDP socket: %s\n", strerror(errno));
		return -1;
	}

	if (ipv6) {
		/* RFC 4795, section 2.5 recommends to set TTL to 255 for UDP */
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &TTL, sizeof(TTL)) < 0) {
			log_err("Failed to set IPv6 unicast hops socket option: %s\n", strerror(errno));
			goto err;
		}

		if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &TTL, sizeof(TTL)) < 0) {
			log_err("Failed to set IPv6 multicast hops socket option: %s\n", strerror(errno));
			goto err;
		}
	} else {
		/* RFC 4795, section 2.5 recommends to set TTL to 255 for UDP */
		if (setsockopt(sock, IPPROTO_IP, IP_TTL, &TTL, sizeof(TTL)) < 0) {
			log_err("Failed to set IPv4 unicast TTL socket option: %s\n", strerror(errno));
			goto err;
		}

		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &TTL, sizeof(TTL)) < 0) {
			log_err("Failed to set IPv4 multicast TTL socket option: %s\n", strerror(errno));
			goto err;
		}
	}

	if (iface != NULL) {
		ifindex = if_nametoindex(iface);

		if (ifindex == 0 && errno != 0) {
			log_err("Could not get interface %s: %s\n", iface, strerror(errno));
			goto err;
		}

		if (ipv6) {
			if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
				log_err("Failed to set interface '%s' for IPv6 multicast socket: %s\n",
					iface, strerror(errno));
				goto err;
			}
		} else {
			struct ip_mreqn mreq;

			memset(&mreq, 0, sizeof(mreq));
			mreq.imr_ifindex = ifindex;

			if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &mreq, sizeof(mreq)) < 0) {
				log_err("Failed to set interface '%s' for IPv4 multicast socket: %s\n",
					iface, strerror(errno));
				goto err;
			}
		}
	}

	p = pkt_alloc(128);

	log_info("LLMNR query: %s IN %s\n", query_name, query_type(qtype));

	for (i = 0; i < count; i++) {
		struct llmnr_hdr *hdr;
		struct sockaddr_storage sst;
		socklen_t sst_len;
		struct iovec iov[1];
		struct msghdr msg;
		struct in6_pktinfo ipi6;
		uint8_t c[CMSG_SPACE(sizeof(ipi6))];
		size_t query_pkt_len;
		fd_set rfds;
		struct timeval tv;
		int ret;

		hdr = (struct llmnr_hdr *)pkt_put(p, sizeof(*hdr));
		hdr->id = htons(id + i % UINT16_MAX);
		hdr->flags = 0;
		hdr->qdcount = htons(1);
		hdr->ancount = 0;
		hdr->nscount = 0;
		hdr->arcount = 0;

		pkt_put_u8(p, (uint8_t)query_name_len);
		memcpy(pkt_put(p, query_name_len), query_name, query_name_len);
		pkt_put_u8(p, 0);

		pkt_put_u16(p, htons(qtype));
		pkt_put_u16(p, htons(LLMNR_QCLASS_IN));

		memset(&sst, 0, sizeof(sst));
		memset(&iov, 0, sizeof(iov));
		memset(&msg, 0, sizeof(msg));
		memset(&ipi6, 0, sizeof(ipi6));

		if (ipv6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&sst;
			struct cmsghdr *cmsg;

			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = htons(LLMNR_UDP_PORT);
			if (inet_pton(AF_INET6, LLMNR_IPV6_MCAST_ADDR, &sin6->sin6_addr) != 1) {
				log_err("Failed to convert IPv6 address: %s\n", strerror(errno));
				break;
			}
			sst_len = sizeof(*sin6);

			ipi6.ipi6_ifindex = ifindex;
			msg.msg_control = c;
			msg.msg_controllen = sizeof(c);
			cmsg = CMSG_FIRSTHDR(&msg);
			cmsg->cmsg_level = IPPROTO_IPV6;
			cmsg->cmsg_type = IPV6_PKTINFO;
			cmsg->cmsg_len = CMSG_LEN(sizeof(ipi6));
			memcpy(CMSG_DATA(cmsg), &ipi6, sizeof(ipi6));
		} else {
			struct sockaddr_in *sin = (struct sockaddr_in *)&sst;

			sin->sin_family = AF_INET;
			sin->sin_port = htons(LLMNR_UDP_PORT);
			if (inet_pton(AF_INET, LLMNR_IPV4_MCAST_ADDR, &sin->sin_addr) != 1) {
				log_err("Failed to convert IPv4 address: %s\n", strerror(errno));
				break;
			}
			sst_len = sizeof(*sin);
		}

		iov[0].iov_base = p->data;
		iov[0].iov_len = pkt_len(p);
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		msg.msg_name = &sst;
		msg.msg_namelen = sst_len;

		if (sendmsg(sock, &msg, 0) < 0) {
			log_err("Failed to send UDP packet: %s\n", strerror(errno));
			break;
		}

		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);

		tv.tv_sec = timeout_ms / 1000;
		tv.tv_usec = (timeout_ms % 1000) * 1000;

		ret = select(sock + 1, &rfds, NULL, NULL, &tv);
		if (ret < 0) {
			log_err("Failed to select() on socket: %s\n", strerror(errno));
			break;
		} else if (ret) {
			uint16_t j, ancount;

			/* save query length and re-use packet for RX */
			query_pkt_len = pkt_len(p) - sizeof(*hdr);
			pkt_reset(p);

			if (recv(sock, p->data, p->size, 0) < 0) {
				log_err("Failed to receive from socket: %s\n", strerror(errno));
				break;
			}

			hdr = (struct llmnr_hdr *)pkt_put(p, sizeof(*hdr));
			ancount = htons(hdr->ancount);

			if (ancount == 0) {
				log_info("LLMNR response: no answer records returned\n");
				continue;
			}

			/* skip the original query */
			pkt_put(p, query_pkt_len);

			for (j = 0; j < ancount; ++j) {
				uint8_t nl = pkt_put_extract_u8(p);
				char addr[INET6_ADDRSTRLEN + 1];
				uint16_t type, clss, addr_size;
				uint32_t ttl;
				char name[LLMNR_LABEL_MAX_SIZE + 1];
				int af;

				/* compression? */
				if (nl & 0xC0) {
					uint16_t ptr = (nl & 0x3F) << 8 | pkt_put_extract_u8(p);
					if (ptr < p->size - 1) {
						uint8_t nnl = p->data[ptr];
						strncpy(name, (char *)&p->data[ptr + 1], nnl);
					} else
						strncpy(name, "<invalid>", LLMNR_LABEL_MAX_SIZE);
				} else
					strncpy(name, (char *)pkt_put(p, nl + 1), nl);

				name[LLMNR_LABEL_MAX_SIZE] = '\0';

				type = htons(pkt_put_extract_u16(p));
				clss = htons(pkt_put_extract_u16(p));

				if (clss != LLMNR_CLASS_IN)
					log_warn("Unexpected response class received: %d\n", clss);

				ttl = htonl(pkt_put_extract_u32(p));
				addr_size = htons(pkt_put_extract_u16(p));

				if (addr_size == sizeof(struct in_addr)) {
					af = AF_INET;
				} else if (addr_size == sizeof(struct in6_addr)) {
					af = AF_INET6;
				} else {
					log_warn("Unexpected address size received: %d\n", addr_size);
					break;
				}

				memcpy(&sst, pkt_put(p, addr_size), addr_size);
				if (!inet_ntop(af, &sst, addr, ARRAY_SIZE(addr)))
					strncpy(addr, "<invalid>", sizeof(addr));
				addr[INET6_ADDRSTRLEN] = '\0';

				log_info("LLMNR response: %s IN %s %s (TTL %d)\n", name, query_type(type), addr, ttl);
			}
		} else
			log_info("No LLMNR response received within timeout (%lu ms)\n", timeout_ms);

		if (i < count - 1) {
			pkt_reset(p);
			usleep(interval_ms * 1000);
		}
	}

	pkt_free(p);
err:
	close(sock);
	return 0;
}
