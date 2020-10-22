#ifndef ACTION_GETTER_H
#define ACTION_GETTER_H

#include <vector>
#include "RuleHeader.h"
#include "Matcher.h"
#include "Constant.h"
#include "CommonUtil.h"

int rule_action_to_app_action(RuleHeader rule);
int get_action(std::string protocol, std::string srcIp, std::string srcPort, std::string dstIp, std::string dstPort, std::vector<RuleHeader> &rules, int mode);

#endif