#ifndef COMMON_UTIL_H
#define COMMON_UTIL_H

#include <iostream>
#include <algorithm>
#include <array>
#include <memory>

std::string packet_info_to_string(std::string protocol, std::string src_ip, std::string src_port, std::string dst_ip, std::string dst_port, bool drop, std::string reason);
std::string exec(const char *cmd);
double get_cpu_usage();

#endif