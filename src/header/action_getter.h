#ifndef ACTION_GETTER_H
#define ACTION_GETTER_H

#include <vector>
#include <sstream>
#include "rule_header.h"
#include "packet_matcher.h"
#include "constant.h"
#include "common_util.h"

int rule_action_to_app_action(rule_header rule);
int get_action(std::string protocol, std::string src_ip, std::string src_port, std::string dst_ip, std::string dst_port, std::string *reason, std::vector<rule_header> &rules);

#endif