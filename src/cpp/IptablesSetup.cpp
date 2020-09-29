#include "../header/IptablesSetup.h"

void clearIptables()
{
	char *cmd = "iptables";
	char *args[] = {cmd, "-F", NULL};

	int pid = fork();
	if (pid == 0)
	{
		execvp(cmd, args);
	}
}

void addRuleToIptables(RuleHeader rule, char *flow)
{
	if (rule.action.compare("drop") == 0 && (rule.count == 0 || rule.matchPacketCount))
	{
		char *protocol = new char[rule.protocol.length() + 1];
		strcpy(protocol, rule.protocol.c_str());
		char *srcIp = new char[20];
		if (rule.srcIp.compare("any") == 0)
		{
			strcpy(srcIp, "0.0.0.0/0");
		}
		else
		{
			strcpy(srcIp, rule.srcIp.c_str());
		}
		char *dstIp = new char[20];
		if (rule.dstIp.compare("any") == 0)
		{
			strcpy(dstIp, "0.0.0.0/0");
		}
		else
		{
			strcpy(dstIp, rule.dstIp.c_str());
		}
		char *srcPort = new char[6];
		strcpy(srcPort, rule.srcPort.c_str());
		char *dstPort = new char[6];
		strcpy(dstPort, rule.dstPort.c_str());

		if (rule.srcPort.compare("any") == 0 && rule.dstPort.compare("any") == 0)
		{
			char *cmd = "iptables";
			char *args[] = {cmd, "-I", flow, "-p", protocol, "-s", srcIp, "-d", dstIp, "-j", "DROP", NULL};
			int pid = fork();
			if (pid == 0)
			{
				execvp(cmd, args);
			}
		}
		else if (rule.srcPort.compare("any") != 0 && rule.dstPort.compare("any") != 0)
		{
			char *cmd = "iptables";
			char *args[] = {cmd, "-I", flow, "-p", protocol, "-s", srcIp, "-d", dstIp, "--sport", srcPort, "--dport", dstPort, "-j", "DROP", NULL};
			int pid = fork();
			if (pid == 0)
			{
				execvp(cmd, args);
			}
		}
		else if (rule.srcPort.compare("any") == 0 && rule.dstPort.compare("any") != 0)
		{
			char *cmd = "iptables";
			char *args[] = {cmd, "-I", flow, "-p", protocol, "-s", srcIp, "-d", dstIp, "--dport", dstPort, "-j", "DROP", NULL};
			int pid = fork();
			if (pid == 0)
			{
				execvp(cmd, args);
			}
		}
		else if (rule.srcPort.compare("any") != 0 && rule.dstPort.compare("any") == 0)
		{
			char *cmd = "iptables";
			char *args[] = {cmd, "-I", flow, "-p", protocol, "-s", srcIp, "-d", dstIp, "--sport", srcPort, "-j", "DROP", NULL};
			int pid = fork();
			if (pid == 0)
			{
				execvp(cmd, args);
			}
		}
	}
}

void setupIptables(std::vector<RuleHeader> rules)
{
	clearIptables();
	for (auto &rule : rules)
	{
		addRuleToIptables(rule, "INPUT");
		addRuleToIptables(rule, "OUTPUT");
		addRuleToIptables(rule, "FORWARD");
	}
}