/*
 * Simple LLMNR query command.
 *
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

#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "compiler.h"
#include "llmnr-packet.h"
#include "log.h"
#include "pkt.h"

static const char *short_ops = "c:i:p:T:h";
static const struct option long_opts[] = {
	{ "count",	required_argument,	NULL, 'c' },
	{ "interval",	required_argument,	NULL, 'i' },
	{ "type",	required_argument,	NULL, 'T' },
	{ "help",	no_argument,		NULL, 'h' },
	{ NULL,		0,			NULL, 0 },
};

static void __noreturn usage_and_exit(int status)
{
	fprintf(stdout, "Usage: llmnr-query [OPTIONS...] <query-name>\n"
			"Options:\n"
			"  -c, --count     number of queries to send (default: 1)\n"
			"  -i, --interval  interval between queries in ms (default: 500)\n"
			"  -T, --type      LLMNR query type, must be one of A, AAAA, ANY (default: A)\n"
			"  -h, --help      show this help and exit");
	exit(status);
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
	const char *query_name;
	size_t query_name_len;
	unsigned long i, count = 1, interval = 500;
	uint16_t qtype = LLMNR_QTYPE_A;
	struct pkt *p;

	while ((c = getopt_long(argc, argv, short_ops, long_opts, NULL)) != -1) {
		switch (c) {
		case 'c':
			count = strtoul(optarg, NULL, 0);
			break;
		case 'i':
			interval = strtoul(optarg, NULL, 0);
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

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		log_err("Failed to open UDP socket: %s\n", strerror(errno));
		return -1;
	}

	p = pkt_alloc(128);

	log_info("LLMNR query: %s IN %s\n", query_name, query_type(qtype));

	for (i = 0; i < count; i++) {
		struct llmnr_hdr *hdr;
		struct sockaddr_in sin;
		size_t query_pkt_len;
		fd_set rfds;
		struct timeval tv;
		int ret;

		hdr = (struct llmnr_hdr *)pkt_put(p, sizeof(*hdr));
		hdr->id = htons(i % UINT16_MAX);
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

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = inet_addr(LLMNR_IPV4_MCAST_ADDR);
		sin.sin_port = htons(LLMNR_UDP_PORT);

		query_pkt_len = pkt_len(p) - sizeof(*hdr);

		if (sendto(sock, p->data, pkt_len(p), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
			log_err("Failed to send UDP packet: %s\n", strerror(errno));
			break;
		}

		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);

		/* wait up to one second for a response */
		tv.tv_sec = 1;
		tv.tv_usec = 0;

		ret = select(sock + 1, &rfds, NULL, NULL, &tv);
		if (ret < 0) {
			log_err("Failed to select() on socket: %s\n", strerror(errno));
			break;
		} else if (ret) {
			uint16_t j, ancount;

			pkt_reset(p);
			if (recv(sock, p->data, p->size, 0) < 0) {
				log_err("Failed to receive from socket: %s\n", strerror(errno));
				break;
			}

			hdr = (struct llmnr_hdr *)pkt_put(p, sizeof(*hdr));
			ancount = htons(hdr->ancount);

			/* skip the original query */
			pkt_put(p, query_pkt_len);

			for (j = 0; j < ancount; ++j) {
				uint8_t nl = *pkt_put(p, 1);
				char addr[INET6_ADDRSTRLEN];
				uint16_t type, clss, addr_size;
				uint32_t ttl;
				char *name;
				int af;

				/* compression? */
				if (nl & 0xC0) {
					uint16_t ptr = (nl & 0x3F) << 8 | *pkt_put(p, 1);
					name = (char *)p->data + ptr;
				} else
					name = (char *)pkt_put(p, nl + 1);

				type = htons(*(uint16_t *)pkt_put(p, sizeof(type)));
				clss = htons(*(uint16_t *)pkt_put(p, sizeof(clss)));
				ttl = htonl(*(uint32_t *)pkt_put(p, sizeof(ttl)));
				addr_size = htons(*(uint16_t *)pkt_put(p, sizeof(addr_size)));

				if (addr_size == sizeof(struct in_addr)) {
					af = AF_INET;
				} else if (addr_size == sizeof(struct in6_addr)) {
					af = AF_INET6;
				} else {
					log_warn("Unexpected address size received: %d\n", addr_size);
					break;
				}

				if (!inet_ntop(af, pkt_put(p, addr_size), addr, ARRAY_SIZE(addr)))
					strncpy(addr, "<invalid>", sizeof(addr));

				log_info("LLMNR response: %s IN %s %s (TTL %d)\n", name, query_type(type), addr, ttl);
			}
		} else
			log_info("No LLMNR response received within timeout\n");

		if (i < count - 1) {
			pkt_reset(p);
			usleep(interval * 1000);
		}
	}

	pkt_free(p);

	close(sock);

	return 0;
}
