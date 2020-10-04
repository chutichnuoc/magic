#ifndef IPTABLES_SETUP_H
#define IPTABLES_SETUP_H

#include "stdlib.h"
#include "PlatformSpecificUtils.h"
#include <iostream>
#include <bits/stdc++.h>
#include "RuleHeader.h"
#include <vector>

void backupIptalbes();
void restoreIptalbes();
void clearIptables();
void addRuleToIptables(RuleHeader rule, std::string flow);
void setupIptables(std::vector<RuleHeader> rules);

#endif