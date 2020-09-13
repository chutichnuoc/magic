#ifndef RULE_READER_H
#define RULE_READER_H

#include <iostream>
#include <vector> 
#include <fstream>
#include <sstream>
#include "RuleHeader.h"

std::vector<RuleHeader> getRules(std::string filePath);
std::string getOptionValueByKey(std::string option, std::string key);

#endif