#ifndef RULE_READER_H
#define RULE_READER_H

#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>
#include "RuleHeader.h"

std::vector<RuleHeader> get_rules(std::string filePath);
std::string get_option_value_by_key(std::string option, std::string key);

#endif