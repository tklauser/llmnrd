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

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include "iface.h"
#include "log.h"
#include "pkt.h"
#include "socket.h"

#include "llmnr-packet.h"
#include "llmnr.h"

static bool llmnr_running = true;
/*
 * Host name in DNS name format (length octet + name + 0 byte)
 */
static char llmnr_hostname[LLMNR_LABEL_MAX_SIZE + 2];

static bool llmnr_name_matches(const uint8_t *query)
{
	uint8_t i, n = llmnr_hostname[0];

	/* length */
	if (query[0] != n)
		return false;
	/* NULL byte */
	if (query[1 + n] != 0)
		return false;

	for (i = 1; i < llmnr_hostname[0]; i++)
		if (tolower(query[i]) != tolower(llmnr_hostname[i]))
			return false;
	return true;
}

static void llmnr_respond(unsigned int ifindex, const struct llmnr_hdr *hdr,
			  const uint8_t *query, size_t query_len, int sock,
			  const struct sockaddr *sa)
{
	uint16_t qtype, qclass;
	uint8_t name_len = query[0];
	/* skip name length & additional '\0' byte */
	const uint8_t *query_name_end = query + name_len + 2;
	size_t i, n, response_len;
	unsigned char family = AF_UNSPEC;
	/*
	 * arbitrary restriction to 16 addresses per interface for the
	 * sake of a simple, atomic interface
	 */
	struct sockaddr_storage addrs[16];
	struct pkt *p;
	struct llmnr_hdr *r;

	if ((query_len - name_len - 2) < 4) {
		log_err("Invalid query format\n");
		return;
	}

	qtype = ntohs(*((uint16_t *)query_name_end));
	qclass = ntohs(*((uint16_t *)query_name_end + 1));

	log_info("query len: %zu type %04x class %04x\n", query_len - name_len - 2, qtype, qclass);

	if (qclass != LLMNR_QCLASS_IN) {
		log_dbg("Unsupported QCLASS: %04x\n", qclass);
		return;
	}

	switch (qtype) {
	case LLMNR_QTYPE_A:
		family = AF_INET;
		break;
	case LLMNR_QTYPE_AAAA:
		family = AF_INET6;
		break;
	case LLMNR_QTYPE_ANY:
		family = AF_UNSPEC;
		break;
	default:
		log_dbg("Unsupported QTYPE: %04x\n", qtype);
		return;
	}

	n = iface_addr_lookup(ifindex, family, addrs, ARRAY_SIZE(addrs));

	/*
	 * This is the max response length (i.e. using all IPv6 addresses and
	 * not message compression). We might not use all of it.
	 */
	response_len = n * (1 + name_len + 1 + 2 + 2 + 4 + 2 + sizeof(struct in6_addr));
	p = pkt_alloc(sizeof(*hdr) + query_len + response_len);

	/* fill the LLMNR header */
	r = (struct llmnr_hdr *)pkt_put(p, sizeof(*r));
	r->id = hdr->id;
	/* response flag */
	r->flags = htons(LLMNR_F_QR);
	r->qdcount = hdr->qdcount;
	r->ancount = htons(n);
	r->nscount = 0;
	r->arcount = 0;

	/* copy the original question */
	memcpy(pkt_put(p, query_len), query, query_len);

	/* append an RR for each address */
	for (i = 0; i < n; i++) {
		void *addr;
		size_t addr_size;
		uint16_t type;

		if (addrs[i].ss_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&addrs[i];
			addr = &sin->sin_addr;
			addr_size = sizeof(sin->sin_addr);
			type = LLMNR_TYPE_A;
		} else if (addrs[i].ss_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addrs[i];
			addr = &sin6->sin6_addr;
			addr_size = sizeof(sin6->sin6_addr);
			type = LLMNR_TYPE_AAAA;
		} else {
			/* skip */
			continue;
		}

		/*
		 * NAME
		 *
		 * TODO: Implement message compression (RFC 1035,
		 * section 4.1.3)
		 */
		memcpy(pkt_put(p, llmnr_hostname[0] + 2), llmnr_hostname, llmnr_hostname[0] + 2);
		/* TYPE */
		pkt_put_u16(p, htons(type));
		/* CLASS */
		pkt_put_u16(p, htons(LLMNR_CLASS_IN));
		/* TTL */
		pkt_put_u32(p, htonl(LLMNR_TTL_DEFAULT));
		/* RDLENGTH */
		pkt_put_u16(p, htons(addr_size));
		/* RDATA */
		memcpy(pkt_put(p, addr_size), addr, addr_size);
	}

	if (sendto(sock, p->data, pkt_len(p), 0, sa, sizeof(struct sockaddr_in)) < 0) {
		log_err("Failed to send response: %s\n", strerror(errno));
	}

	pkt_free(p);
}

static void llmnr_packet_process(unsigned int ifindex, const uint8_t *pktbuf, size_t len,
				 int sock, const struct sockaddr *sa)
{
	const struct llmnr_hdr *hdr = (const struct llmnr_hdr *)pktbuf;
	uint16_t id, flags, qdcount;
	char rhost[INET6_ADDRSTRLEN];
	char ifname[IF_NAMESIZE];
	const void *addr = NULL;
	const uint8_t *query;
	size_t query_len;
	uint8_t name_len;

	if (sa->sa_family == AF_INET)
		addr = &((const struct sockaddr_in *)sa)->sin_addr;
	else if (sa->sa_family == AF_INET6)
		addr = &((const struct sockaddr_in6 *)sa)->sin6_addr;

	if (!addr || !inet_ntop(sa->sa_family, addr, rhost, sizeof(rhost)))
		strncpy(rhost, "<unknown>", sizeof(rhost) - 1);

	if (len < sizeof(struct llmnr_hdr)) {
		log_warn("Short packet received (%zu bytes) from host %s\n", len, rhost);
		return;
	}

	id = ntohs(hdr->id);
	flags = ntohs(hdr->flags);
	qdcount = ntohs(hdr->qdcount);

	log_info("LLMNR packet (%zu bytes) from host %s on interface %s\n", len,
		 rhost, if_indextoname(ifindex, ifname));
	log_info("[ id 0x%04x flags %04x qdcount %04x ]\n", id, flags, qdcount);

	if (((flags & (LLMNR_F_QR | LLMNR_F_OPCODE)) != 0) ||
	    qdcount != 1 || hdr->ancount != 0 || hdr->nscount != 0) {
		/* silently discard invalid queries */
		return;
	}

	query = pktbuf + sizeof(struct llmnr_hdr);
	query_len = len - sizeof(struct llmnr_hdr);
	name_len = query[0];
	if (name_len == 0 || name_len >= query_len || query[1 + name_len] != 0) {
		log_warn("Invalid query format received from host %s\n", rhost);
		return;
	}

	log_info("[ query %s (%zu bytes) ]\n", (char*)query + 1, query_len);
	if (query_len > name_len && llmnr_name_matches(query)) {
		llmnr_respond(ifindex, hdr, query, query_len, sock, sa);
	}
}

int llmnr_run(const char *hostname, uint16_t port)
{
	int ret = -1;
	int sock;

	if (port == 0)
		port = LLMNR_UDP_PORT;

	llmnr_hostname[0] = strlen(hostname);
	strncpy(&llmnr_hostname[1], hostname, LLMNR_LABEL_MAX_SIZE);
	llmnr_hostname[LLMNR_LABEL_MAX_SIZE + 1] = '\0';
	log_info("Listening on port %u, hostname %s\n", port, hostname);

	sock = socket_open_v4(port);
	if (sock < 0)
		return -1;

	while (llmnr_running) {
		uint8_t pktbuf[2048], aux[128];
		struct msghdr msg;
		struct iovec io;
		struct sockaddr_in saddr_r;
		struct cmsghdr *cmsg;
		ssize_t recvlen;
		unsigned int ifindex = 0;

		io.iov_base = pktbuf;
		io.iov_len = sizeof(pktbuf);

		memset(&msg, 0, sizeof(msg));
		msg.msg_name = &saddr_r;
		msg.msg_namelen = sizeof(saddr_r);
		msg.msg_iov = &io;
		msg.msg_iovlen = 1;
		msg.msg_control = aux;
		msg.msg_controllen = sizeof(aux);

		if ((recvlen = recvmsg(sock, &msg, 0)) < 0) {
			if (errno != EINTR)
				log_err("Failed to receive packet: %s\n", strerror(errno));
			goto out;
		}

		for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
			if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
				struct in_pktinfo *info = (struct in_pktinfo *)CMSG_DATA(cmsg);
				ifindex = info->ipi_ifindex;
			}
		}

		llmnr_packet_process(ifindex, pktbuf, recvlen, sock, (const struct sockaddr *)&saddr_r);
	}

	ret = 0;
out:
	close(sock);
	return ret;
}

void llmnr_stop(void)
{
	llmnr_running = false;
}
