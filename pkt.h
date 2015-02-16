/*
 * Packet buffer structure and utilities.
 *
 * Copyright (C) 2015 Tobias Klauser <tklauser@distanz.ch>
 *
 * Based on pkt_buff.h from the netsniff-ng toolkit which is:
 *
 * Copyright (C) 2012 Christoph Jaeger
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

#ifndef PKT_H
#define PKT_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "log.h"
#include "util.h"

struct pkt {
	uint8_t *data;
	uint8_t *tail;
	size_t size;
};

static inline bool pkt_invariant(struct pkt *p)
{
	return p && (p->data <= p->tail);
}

static inline struct pkt *pkt_alloc(size_t size)
{
	struct pkt *p = xmalloc(sizeof(*p) + size);
	uint8_t *data = (uint8_t *)p + sizeof(*p);

	p->data = p->tail = data;
	p->size = size;

	return p;
}

static inline void pkt_free(struct pkt *p)
{
	free(p);
}

static inline size_t pkt_len(struct pkt *p)
{
	assert(pkt_invariant(p));

	return p->tail - p->data;
}

static inline uint8_t *pkt_put(struct pkt *p, size_t len)
{
	uint8_t *data;

	assert(pkt_invariant(p));

	if (len <= pkt_len(p)) {
		data = p->tail;
		p->tail += len;
	} else {
		/* grow packet */
		size_t new_size = p->size + len - pkt_len(p);
		struct pkt *np = xrealloc(p, sizeof(*np) + new_size);

		log_dbg("Reallocating packet from %zu to %zu bytes\n", p->size, new_size);
		data = (uint8_t *)np + sizeof(*np);

		np->data = data;
		np->tail = data + pkt_len(p);
	}

	return data;
}

static inline void pkt_put_u16(struct pkt *p, uint16_t val)
{
	uint16_t *data = (uint16_t *)pkt_put(p, sizeof(val));
	*data = val;
}

static inline void pkt_put_u32(struct pkt *p, uint32_t val)
{
	uint32_t *data = (uint32_t *)pkt_put(p, sizeof(val));
	*data = val;
}

#endif /* PKT_H */
