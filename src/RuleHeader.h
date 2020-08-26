#ifndef RULE_HEADER
#define RULE_HEADER

#include <string>
#include "stdlib.h"

class RuleHeader
{
public:
    std::string action;
    std::string protocol;
    std::string srcIp;
    std::string srcPort;
    std::string dstIp;
    std::string dstPort;

    RuleHeader(std::string action, std::string protocol, std::string srcIp, std::string srcPort, std::string dstIp, std::string dstPort)
    {
        this->action = action;
        this->protocol = protocol;
        this->srcIp = srcIp;
        this->srcPort = srcPort;
        this->dstIp = dstIp;
        this->dstPort = dstPort;
    }
};

#endif