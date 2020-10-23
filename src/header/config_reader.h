#ifndef CONFIG_READER_H
#define CONFIG_READER_H

#include <fstream>
#include <sstream>

void set_config_file_path(std::string path);

std::string get_config_value(std::string key);

#endif