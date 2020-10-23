#ifndef PROTOCOL_HANDLER_H
#define PROTOCOL_HANDLER_H

#include <iostream>
#include <arpa/inet.h>

#include "../sniff_header/sniff_ip.h"
#include "../sniff_header/sniff_tcp.h"
#include "../sniff_header/sniff_udp.h"

void handle_tcp(const u_char *packet, int size_ip, std::string *src_port, std::string *dst_port);

void handle_udp(const u_char *packet, int size_ip, std::string *src_port, std::string *dst_port);

void handle_ip(const u_char *packet, std::string *protocol, std::string *src_ip, std::string *src_port, std::string *dst_ip, std::string *dst_port);

#endif