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
    std::string srcIp;
    std::string srcPort;
    std::string dstIp;
    std::string dstPort;

    int size = 0;
    int time = 0;
    int count = 0;

    clock_t startTime;
    int packetCount = 0;
    bool matchPacketCount = true;

    RuleHeader(std::string action, std::string protocol, std::string srcIp, std::string srcPort, std::string dstIp, std::string dstPort)
    {
        this->action = action;
        this->protocol = protocol;
        this->srcIp = srcIp;
        this->srcPort = srcPort;
        this->dstIp = dstIp;
        this->dstPort = dstPort;
    }

    void toString()
    {
        std::cout << this->action << " " << this->protocol << " " << this->srcIp << " " << this->srcPort << " -> " << this->dstIp << " " << this->dstPort << std::endl;
        std::cout << this->size << " " << this->time << " " << this->count << std::endl;
    }
};

#endif