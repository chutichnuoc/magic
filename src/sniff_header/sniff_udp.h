#ifndef SNIFF_UDP_H
#define SNIFF_UDP_H

#include <sys/types.h>

/* Udp header */
struct sniff_udp {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* udp length */
	u_short	uh_sum;			/* udp checksum */
};

#endif