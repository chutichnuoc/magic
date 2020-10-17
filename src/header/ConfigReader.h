#ifndef CONFIG_READER_H
#define CONFIG_READER_H

#include <iostream>
#include <fstream>
#include <sstream>

void setConfigFilePath(std::string path);

std::string getConfigValue(std::string key);

#endif