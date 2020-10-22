#ifndef RULE_HEADER
#define RULE_HEADER

#include <string>
#include "stdlib.h"
#include <iostream>

class RuleHeader
{
public:
    std::string action;
    std::string protocol;
    std::string src_ip;
    std::string src_port;
    std::string dst_ip;
    std::string dst_port;

    int time = 0;
    int count = 0;

    clock_t start_time;
    int packet_count = 0;
    bool match_packet_count = true;

    RuleHeader(std::string action, std::string protocol, std::string src_ip, std::string src_port, std::string dst_ip, std::string dst_port)
    {
        this->action = action;
        this->protocol = protocol;
        this->src_ip = src_ip;
        this->src_port = src_port;
        this->dst_ip = dst_ip;
        this->dst_port = dst_port;
    }

    void toString()
    {
        std::cout << this->action << " " << this->protocol << " " << this->src_ip << " " << this->src_port << " -> " << this->dst_ip << " " << this->dst_port << std::endl;
        std::cout << this->time << " " << this->count << std::endl;
    }
};

#endif