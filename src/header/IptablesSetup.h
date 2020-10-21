#ifndef IPTABLES_SETUP_H
#define IPTABLES_SETUP_H

#include "stdlib.h"
#include "PlatformSpecificUtils.h"
#include <iostream>
#include <bits/stdc++.h>
#include "RuleHeader.h"
#include <vector>
#include "../header/ConfigReader.h"

void backupIptalbes();
void restoreIptalbes();
void clearIptables();
void setupIptables(std::string interface);

#endif