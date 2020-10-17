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

void addRuleToIptables(RuleHeader rule, std::string flow)
{
	if (rule.action.compare("drop") == 0 && (rule.count == 0 || rule.matchPacketCount))
	{
		std::string protocol = "";
		std::string srcIp = "";
		std::string dstIp = "";
		std::string action = "DROP";
		std::string command = "iptables -I " + flow;
		if (rule.protocol.compare("ip") == 0)
		{
			protocol = "all";
		}
		else
		{
			protocol = rule.protocol;
		}
		command += " -p " + protocol;
		if (rule.srcIp.compare("any") == 0)
		{
			srcIp = "0.0.0.0/0";
		}
		else
		{
			srcIp = rule.srcIp;
		}
		if (rule.dstIp.compare("any") == 0)
		{
			dstIp = "0.0.0.0/0";
		}
		else
		{
			dstIp = rule.dstIp;
		}
		command += " -s " + srcIp + " -d " + dstIp;
		if (rule.srcPort.compare("any") != 0)
		{
			command += " --sport " + rule.srcPort;
		}
		if (rule.dstPort.compare("any") != 0)
		{
			command += " --dport " + rule.dstPort;
		}
		command += " -j " + action;
		system(command.c_str());
	}
}

void setupIptables(std::vector<RuleHeader> rules)
{
	backupIptalbes();
	for (auto &rule : rules)
	{
		addRuleToIptables(rule, "INPUT");
		addRuleToIptables(rule, "OUTPUT");
		addRuleToIptables(rule, "FORWARD");
	}
}