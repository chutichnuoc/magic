#ifndef IPTABLES_SETUP_H
#define IPTABLES_SETUP_H

#include "config_reader.h"

void backup_iptables();
void restore_iptables();
void setup_iptables(std::string interface, std::string mode);

#endif