#ifndef LOGGER
#define LOGGER

#include <iostream>
#include <fstream>
#include <ctime>
#include <unistd.h>
#include "../header/ConfigReader.h"

void log_packet_info(std::string message);

#endif