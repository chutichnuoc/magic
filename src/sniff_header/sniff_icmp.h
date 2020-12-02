#ifndef SNIFF_ICMP_H
#define SNIFF_ICMP_H

#include <sys/types.h>

/* Icmp header */
struct sniff_icmp
{
	u_char icmp_type; /* type of message */
	u_char icmp_code; /* type of subcode */
	u_short icmp_sum; /* udp checksum */
	u_int32_t roh;
};

#endif