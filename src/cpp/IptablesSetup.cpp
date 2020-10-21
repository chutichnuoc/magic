#include "../header/IptablesSetup.h"

void backupIptalbes()
{
	std::string iptablesFile = getConfigValue("iptablesFile");
	std::string command = "iptables-save > " + iptablesFile;
	system(command.c_str());
}

void restoreIptalbes()
{
	std::string iptablesFile = getConfigValue("iptablesFile");
	std::string command = "iptables-restore < " + iptablesFile;
	system(command.c_str());
}

void clearIptables()
{
	std::string command = "iptables -F";
	system(command.c_str());
}

void setupIptables(std::string interface)
{
	backupIptalbes();
	std::string command = "iptables -I FORWARD -j NFQUEUE -i " + interface;
	system(command.c_str());
}