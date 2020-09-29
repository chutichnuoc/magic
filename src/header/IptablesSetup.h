#ifndef IPTABLES_SETUP_H
#define IPTABLES_SETUP_H

#include "stdlib.h"
#include "PlatformSpecificUtils.h"
#include <iostream>
#include <bits/stdc++.h>
#include "RuleHeader.h"
#include <vector>

void clearIptables();
void addRuleToIptables(RuleHeader rule, char *flow);
void setupIptables(std::vector<RuleHeader> rules);

#endif