/*
 * Copyright (C) 2014-2017 Tobias Klauser <tklauser@distanz.ch>
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
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include "iface.h"
#include "log.h"
#include "pkt.h"
#include "socket.h"

#include "iface.h"
#include "llmnr-packet.h"
#include "llmnr.h"

static bool llmnr_ipv6 = false;
/* Host name in DNS name format (length octet + name + 0 byte) */
static char llmnr_hostname[LLMNR_LABEL_MAX_SIZE + 2];

void llmnr_set_hostname(const char *hostname)
{
	llmnr_hostname[0] = strlen(hostname);
	strncpy(&llmnr_hostname[1], hostname, LLMNR_LABEL_MAX_SIZE);
	llmnr_hostname[LLMNR_LABEL_MAX_SIZE + 1] = '\0';
}

void llmnr_init(const char *hostname, bool ipv6)
{
	llmnr_set_hostname(hostname);
	llmnr_ipv6 = ipv6;
}

struct llmnr_alias_t 
{
	struct llmnr_alias_t * next;
	char                   name[2]; // allocate additional space, always need len prefix and terminating \0.
};

static struct llmnr_alias_t *llmnr_aliases = NULL;

void llmnr_add_alias(const char *alias)
{
	struct llmnr_alias_t *a = (struct llmnr_alias_t*)malloc(sizeof(*a)+strlen(alias));
	if (!a)
		return;
	a->name[0] = strlen(alias);
	strcpy(&a->name[1], alias);
	a->next = llmnr_aliases;
	llmnr_aliases = a;
}


static size_t get_dns_name_length(const uint8_t *query, size_t query_len)
{
	size_t ret = 0;
	while (ret+1 < query_len) {
		uint8_t len = query[ret];
		if (len > LLMNR_LABEL_MAX_SIZE)
			return 0;
		if (!len)
			return ret+1;
		ret += 1+len;
	}
	return 0;
}

static int dns_is_reverse_query(const uint8_t *query)
{
	size_t len = strlen((const char*)query);
	uint16_t query_type;
	uint16_t query_class;

	// check wether query ends on ".arpa"
	if (len < 5 || query[len-5]!= 4 || strcasecmp((const char*)&query[len-4], "arpa") != 0)
		return 0;

	memcpy(&query_type,  &query[len+1], 2);
	memcpy(&query_class, &query[len+3], 2);

	if (query_class != htons(LLMNR_CLASS_IN))
		return 0;

	if ( query_type != htons(LLMNR_TYPE_PTR)  && 
	     query_type != htons(LLMNR_QTYPE_ANY)    )
		return 0;

	// check wether query ends on ".in-addr.arpa"
	if (len > 13 && query[len-13]==7 && strncasecmp( (const char*)&query[len-12], "in-addr", 7) ==0)
		return AF_INET;

	// check wether query ends on ".ip6.arpa"
	if (len == 73 && query[len-9]==3 && strncasecmp((const char*) &query[len-8], "ip6", 3) ==0)
		return AF_INET6;

	return 0;
}

#define MATCH_NAME  1
#define MATCH_ALIAS 2
#define MATCH_ADDR  3

static int llmnr_name_matches(int ifindex, const uint8_t *query)
{
	struct llmnr_alias_t *a;
	uint8_t n;

	int af = dns_is_reverse_query(query);
	
	if (af) {
		int i;
		unsigned x;
		char buffer[4];
		uint8_t query_addr[16];
		struct sockaddr_storage addrs[16];
		int n;

		if (af == AF_INET) {
			for (i=4; i--;) {
				uint8_t n = query[0];
				if (n < 1 || n > 3)
					return 0;
				memcpy(buffer, query+1, n);
				buffer[n]='\0';
				if (sscanf(buffer, "%d", &x) != 1)
					return 0;
				query_addr[i]=x;
				query += n+1;
			}
		} else if (af == AF_INET6) {
			for (i=16; i--;) {
				if (query[0] != 1 || query[2] != 1)
					return 0;
				buffer[0]=query[3];
				buffer[1]=query[1];
				buffer[2]='\0';
				if (sscanf(buffer, "%x", &x) != 1)
					return 0;
				query_addr[i]=x;
				query +=4;
			}
		} else
			return 0;

		n = iface_addr_lookup(ifindex, af, addrs, ARRAY_SIZE(addrs));
		/* Don't respond if no address was found for the given interface */
		if (n == 0)
			return 0;

		for (i = 0; i < n; i++) {
			void *addr;
			size_t addr_size;

			if (addrs[i].ss_family != af)
				continue;

			if (af == AF_INET) {
				struct sockaddr_in *sin = (struct sockaddr_in *)&addrs[i];
				addr = &sin->sin_addr;
				addr_size = sizeof(sin->sin_addr);
			} else if (af == AF_INET6) {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addrs[i];
				addr = &sin6->sin6_addr;
				addr_size = sizeof(sin6->sin6_addr);
			} else
				return 0;

			if (memcmp(query_addr, addr, addr_size)==0)
				return MATCH_ADDR;
		}
	}


	n = llmnr_hostname[0];
	if (query[0] == n && query[1 + n] == 0 && strncasecmp((const char *)&query[1], &llmnr_hostname[1], n) == 0)
		return MATCH_NAME;

	for (a=llmnr_aliases; a; a = a->next) {
		uint8_t n = a->name[0];

		if (query[0]==n && query[1 + n] == 0 && strncasecmp((const char *)&query[1], &a->name[1], n)==0)
			return MATCH_ALIAS;
	}

	return 0;
}

static void llmnr_respond(unsigned int ifindex, const struct llmnr_hdr *hdr,
			  const uint8_t *query, size_t query_len, int sock,
			  const struct sockaddr_storage *sst, int match)
{
	uint16_t qtype, qclass;
	uint8_t query_name_len = get_dns_name_length(query, query_len);
	/* skip name length & additional '\0' byte */
	const uint8_t *query_name_end = query + query_name_len;
	size_t i, n, response_len;
	unsigned char family = AF_UNSPEC;
	/*
	 * arbitrary restriction to 16 addresses per interface for the
	 * sake of a simple, atomic interface
	 */
	struct sockaddr_storage addrs[16];
	struct pkt *p;
	struct llmnr_hdr *r;
	size_t cname_n;
	size_t cname_len;
	uint16_t name_ptr;

	/* 4 bytes expected for QTYPE and QCLASS */
	if ((query_len - query_name_len) < (sizeof(qtype) + sizeof(qclass)))
		return;

	memcpy(&qtype, query_name_end, sizeof(qtype));
	qtype = ntohs(qtype);
	memcpy(&qclass, query_name_end + sizeof(qtype), sizeof(qclass));
	qclass = ntohs(qclass);

	/* Only IN queries supported */
	if (qclass != LLMNR_QCLASS_IN)
		return;

	/* No AAAA responses if IPv6 is disabled */
	if (!llmnr_ipv6 && qtype == LLMNR_QTYPE_AAAA)
		return;

	if (match == MATCH_ADDR) {
		response_len = 2 + 2 + 2 + 4 + 2 + 1 + llmnr_hostname[0] + 1 ;
		n = 1;
	} else {
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
			return;
		}

		n = iface_addr_lookup(ifindex, family, addrs, ARRAY_SIZE(addrs));
		/* Don't respond if no address was found for the given interface */
		if (n == 0)
			return;
		response_len = n * (2 + 2 + 2 + 4 + 2 + sizeof(struct in6_addr));
	}
	
	cname_n   = (match==MATCH_ALIAS) ? 1 : 0 ;
	cname_len = (match==MATCH_ALIAS) ? (2 + 2 + 2+ 4 + 2 + llmnr_hostname[0] + 2) : 0;
	/*
	 * This is the max response length (i.e. using all IPv6 addresses and
	 * no message compression). We might not use all of it.
	 */
	p = pkt_alloc(sizeof(*hdr) + query_len + cname_len + response_len);

	/* fill the LLMNR header */
	r = (struct llmnr_hdr *)pkt_put(p, sizeof(*r));
	r->id = hdr->id;
	/* response flag */
	r->flags = htons(LLMNR_F_QR);
	r->qdcount = hdr->qdcount;
	r->ancount = htons(n + cname_n);
	r->nscount = 0;
	r->arcount = 0;

	/* get pointer to question name */
	name_ptr=pkt_len(p);
	/* copy the original question */
	memcpy(pkt_put(p, query_len), query, query_len);

	if (match==MATCH_ADDR) {
		/* message compression (RFC 1035, section 4.1.3) */
		pkt_put_u16(p, ntohs(0xC000 | name_ptr));
		/* TYPE */
		pkt_put_u16(p, htons(LLMNR_TYPE_PTR));
		/* CLASS */
		pkt_put_u16(p, htons(LLMNR_CLASS_IN));
		/* TTL */
		pkt_put_u32(p, htonl(LLMNR_TTL_DEFAULT));
		/* RDLENGTH */
		pkt_put_u16(p, htons(llmnr_hostname[0] + 2));
		/* RDATA */
		memcpy(pkt_put(p, llmnr_hostname[0] + 2), llmnr_hostname, llmnr_hostname[0] + 2);
	} else {
		if (match==MATCH_ALIAS) {
			/* message compression (RFC 1035, section 4.1.3) */
			pkt_put_u16(p, ntohs(0xC000 | name_ptr));
			/* TYPE */
			pkt_put_u16(p, htons(LLMNR_TYPE_CNAME));
			/* CLASS */
			pkt_put_u16(p, htons(LLMNR_CLASS_IN));
			/* TTL */
			pkt_put_u32(p, htonl(LLMNR_TTL_DEFAULT));
			/* RDLENGTH */
			pkt_put_u16(p, htons(llmnr_hostname[0] + 2));
			/* RDATA */
			/* update pointer to CNAME target */
			name_ptr = pkt_len(p);
			memcpy(pkt_put(p, llmnr_hostname[0] + 2), llmnr_hostname, llmnr_hostname[0] + 2);
		}

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
			} else
				continue;

			/* NAME */
			/* message compression (RFC 1035, section 4.1.3) */
			pkt_put_u16(p, ntohs(0xC000 | name_ptr));

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
	}

	if (sendto(sock, p->data, pkt_len(p), 0, (struct sockaddr *)sst, sizeof(*sst)) < 0)
		log_err("Failed to send response: %s\n", strerror(errno));

	pkt_free(p);
}

static void llmnr_packet_process(int ifindex, const uint8_t *pktbuf, size_t len,
				 int sock, const struct sockaddr_storage *sst)
{
	const struct llmnr_hdr *hdr = (const struct llmnr_hdr *)pktbuf;
	uint16_t flags, qdcount;
	const uint8_t *query;
	size_t query_len;
	uint8_t name_len;
	int match;

	/* Query too short? */
	if (len < sizeof(struct llmnr_hdr))
		return;

	flags = ntohs(hdr->flags);
	qdcount = ntohs(hdr->qdcount);

	/* Query invalid as per RFC 4795, section 2.1.1 */
	if (((flags & (LLMNR_F_QR | LLMNR_F_OPCODE | LLMNR_F_TC)) != 0) ||
	    qdcount != 1 || hdr->ancount != 0 || hdr->nscount != 0)
		return;

	query = pktbuf + sizeof(struct llmnr_hdr);
	query_len = len - sizeof(struct llmnr_hdr);
	name_len = get_dns_name_length(query, query_len);

	/* Invalid name in query? */
	if (name_len == 0 || name_len+4u > query_len )
		return;

	/* Authoritative? */
	match = llmnr_name_matches(ifindex, query);
	if (match)
		llmnr_respond(ifindex, hdr, query, query_len, sock, sst, match);
}

void llmnr_recv(int sock)
{
	uint8_t pktbuf[2048], aux[128];
	struct msghdr msg;
	struct iovec io;
	struct sockaddr_storage sin_r;
	struct cmsghdr *cmsg;
	ssize_t recvlen;
	int ifindex = -1;

	io.iov_base = pktbuf;
	io.iov_len = sizeof(pktbuf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sin_r;
	msg.msg_namelen = sizeof(sin_r);
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = aux;
	msg.msg_controllen = sizeof(aux);

	if ((recvlen = recvmsg(sock, &msg, 0)) < 0) {
		if (errno != EINTR)
			log_err("Failed to receive packet: %s\n", strerror(errno));
		return;
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo *in = (struct in_pktinfo *)CMSG_DATA(cmsg);
			ifindex = in->ipi_ifindex;
		} else if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo *in6 = (struct in6_pktinfo *)CMSG_DATA(cmsg);
			ifindex = in6->ipi6_ifindex;
		}
	}

	if (ifindex >= 0)
		llmnr_packet_process(ifindex, pktbuf, recvlen, sock,
				     (const struct sockaddr_storage *)&sin_r);
	else
		log_warn("Could not get interface of incoming packet\n");
}
