#ifndef HANDLE_PROTOCOL_H
#define HANDLE_PROTOCOL_H

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "../sniff_header/sniff_tcp.h"
#include "../sniff_header/sniff_udp.h"
#include "../sniff_header/sniff_icmp.h"

void handle_tcp(const u_char *packet, int size_ip, std::string *srcPort, std::string *dstPort);

void handle_udp(const u_char *packet, int size_ip, std::string *srcPort, std::string *dstPort);

#endif