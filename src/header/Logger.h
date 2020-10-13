#ifndef LOGGER
#define LOGGER

#include <iostream>
#include <fstream>
#include <ctime>
#include <unistd.h>
#include "../header/ConfigReader.h"

void getCurrentDir();
void logPacketInfo(std::string message);

#endif