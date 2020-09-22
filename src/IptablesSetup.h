#ifndef IPTABLES_SETUP_H
#define IPTABLES_SETUP_H

#include "stdlib.h"
#include "PlatformSpecificUtils.h"
#include <iostream>
#include <bits/stdc++.h>
#include "RuleHeader.h"

void clearIptables();
void addRuleToIptables(RuleHeader rule);

#endif