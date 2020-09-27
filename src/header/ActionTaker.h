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

void handlePacket(pcpp::Packet parsedPacket, std::vector<RuleHeader> &rules, int mode);
void takeAction(std::string protocol, std::string srcIP, std::string dstIP, int srcPort, int dstPort, std::string action, int mode);

#endif