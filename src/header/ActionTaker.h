#ifndef ACTION_TAKER_H
#define ACTION_TAKER_H

#include <vector>
#include "RuleHeader.h"
#include <iostream>
#include "Matcher.h"
#include "Logger.h"
#include "IptablesSetup.h"
#include "Constant.h"

int get_action(std::string protocol, std::string srcIp, std::string srcPort, std::string dstIp, std::string dstPort, std::vector<RuleHeader> &rules, int mode);

#endif