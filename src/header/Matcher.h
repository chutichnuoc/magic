#ifndef MATCHER_H
#define MATCHER_H

#include "stdlib.h"
#include <iostream>
#include "math.h"
#include <bits/stdc++.h>
#include "RuleHeader.h"

using namespace std;

bool match_protocol(string ruleProtocol, string packetProtocol);

bool match_ip(string ruleIp, string packetIp);

bool match_port(string rulePort, string packetPort);

uint32_t ip_to_int(string ip);

uint32_t get_net_ip(string ruleIp, int start, int end);

bool match_packet(std::string protocol, std::string srcIp, std::string srcPort, std::string dstIp, std::string dstPort, RuleHeader rule);

#endif