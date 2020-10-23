#ifndef RULE_READER_H
#define RULE_READER_H

#include <iostream>
#include <vector>
#include <fstream>
#include <sstream>

#include "rule_header.h"

std::vector<rule_header> get_rules(std::string file_path);
std::string get_option_value_by_key(std::string option, std::string key);

#endif