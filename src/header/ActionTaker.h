#ifndef ACTION_TAKER_H
#define ACTION_TAKER_H

#include <vector>
#include "RuleHeader.h"
#include <iostream>
#include "Parser.h"
#include "Matcher.h"
#include "Logger.h"
#include "IptablesSetup.h"
#include "Constant.h"

int getAction(std::string protocol, std::string srcIp, std::string srcPort, std::string dstIp, std::string dstPort, std::vector<RuleHeader> &rules, int mode);
void takeAction(std::string protocol, std::string srcIP, std::string dstIP, int srcPort, int dstPort, std::string action, int mode);

#endif