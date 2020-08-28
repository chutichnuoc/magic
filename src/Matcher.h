#ifndef MATCHER_H
#define MATCHER_H

#include "stdlib.h"
#include <iostream>
#include "math.h"
#include<bits/stdc++.h> 

using namespace std;

bool matchProtocol(string ruleProtocol, string packetProtocol);

bool matchIp(string ruleIp, string packetIp);

bool matchPort(string rulePort, string packetPort);

uint32_t IPToUInt(string ip);

uint32_t getNetIp(string ruleIp, int start, int end);

#endif