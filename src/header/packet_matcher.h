#ifndef MATCHER_H
#define MATCHER_H

#include "stdlib.h"
#include <iostream>
#include "math.h"
#include <bits/stdc++.h>
#include "rule_header.h"

using namespace std;

bool match_protocol(std::string rule_protocol, std::string packet_protocol);

bool match_ip(std::string rule_ip, std::string packet_ip);

bool match_port(std::string rule_port, std::string packet_port);

uint32_t ip_to_int(std::string ip);

uint32_t get_net_ip(std::string net_ip, int start, int end);

bool match_packet(std::string protocol, std::string src_ip, std::string src_port, std::string dst_ip, std::string dst_port, rule_header rule);

#endif