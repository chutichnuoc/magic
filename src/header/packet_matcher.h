#ifndef MATCHER_H
#define MATCHER_H

#include "stdlib.h"
#include <iostream>
#include "math.h"
#include <bits/stdc++.h>
#include "rule_header.h"

using namespace std;

bool match_protocol(string rule_protocol, string packet_protocol);

bool match_ip(string rule_ip, string packet_ip);

bool match_port(string rule_port, string packet_port);

uint32_t ip_to_int(string ip);

uint32_t get_net_ip(string net_ip, int start, int end);

bool match_packet(std::string protocol, std::string src_ip, std::string src_port, std::string dst_ip, std::string dst_port, rule_header rule);

#endif