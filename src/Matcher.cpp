#include "Matcher.h"

bool matchProtocol(string ruleProtocol, string packetProtocol)
{
	transform(ruleProtocol.begin(), ruleProtocol.end(), ruleProtocol.begin(), ::toupper); 
	return ruleProtocol.compare(packetProtocol) == 0;
}

bool matchIp(string ruleIp, string packetIp)
{
	if (ruleIp.compare("any") == 0 || ruleIp.compare(packetIp) == 0)
	{
		return true;
	}

	bool exclamation = false;
	bool subnet = false;
	int slashIndex = 0;
	int start = 0;
	int end = ruleIp.length() - 1;
	uint32_t netmask;
	uint32_t ip = IPToUInt(packetIp);
	uint32_t netIp;

	if (ruleIp.find('!') != string::npos)
	{
		exclamation = true;
		start = 1;
	}

	slashIndex = ruleIp.find('/');
	if (slashIndex != string::npos)
	{
		subnet = true;
		string mask = ruleIp.substr(slashIndex + 1);
		netmask = static_cast<uint32_t>(stoul(mask));
		end = slashIndex - 1;
	}

	netIp = getNetIp(ruleIp, start, end);

	uint32_t netstart = (netIp & netmask);	 // first ip in subnet
	uint32_t netend = (netstart | ~netmask); // last ip in subnet
	return ((ip >= netstart) && (ip <= netend));
}

bool matchPort(string rulePort, string packetPort)
{
	if (rulePort.compare("any") == 0 || rulePort.compare("any\n") == 0 || packetPort.compare("any") == 0 || rulePort.compare(packetPort) == 0)
	{
		return true;
	}

	if (rulePort.find('!') != string::npos)
	{
		string orgRulePort = rulePort.substr(1, rulePort.length() - 1);
		return !(orgRulePort.compare(packetPort) == 0);
	}
	return false;
}

uint32_t IPToUInt(string ip)
{
	int a, b, c, d;
	uint32_t addr = 0;

	if (sscanf(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4)
		return 0;

	addr = a << 24;
	addr |= b << 16;
	addr |= c << 8;
	addr |= d;
	return addr;
}

uint32_t getNetIp(string ruleIp, int start, int end)
{
	string ip = ruleIp.substr(start, end);
	uint32_t result = static_cast<uint32_t>(stoul(ip));
}