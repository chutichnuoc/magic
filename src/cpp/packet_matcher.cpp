#include "../header/packet_matcher.h"

bool match_protocol(std::string rule_protocol, std::string packet_protocol)
{
	transform(rule_protocol.begin(), rule_protocol.end(), rule_protocol.begin(), ::tolower);
	transform(packet_protocol.begin(), packet_protocol.end(), packet_protocol.begin(), ::tolower);
	return rule_protocol.compare(packet_protocol) == 0 || packet_protocol.compare("ip") == 0 || rule_protocol.compare("ip") == 0;
}

bool match_ip(std::string rule_ip, std::string packet_ip)
{
	if (rule_ip.compare("any") == 0 || rule_ip.compare(packet_ip) == 0)
	{
		return true;
	}

	int start = 0;
	int end = rule_ip.length() - 1;
	uint32_t netmask;
	uint32_t ip = ip_to_int(packet_ip);
	uint32_t net_ip;

	if (rule_ip.find('!') != std::string::npos)
	{
		start = 1;
	}

	int slash_index = rule_ip.find('/');
	if (slash_index != std::string::npos)
	{
		std::string mask = rule_ip.substr(slash_index + 1);
		netmask = static_cast<uint32_t>(stoul(mask));
		end = slash_index - 1;
	}

	net_ip = get_net_ip(rule_ip, start, end);

	if (rule_ip.find('!') != std::string::npos && rule_ip.find('/') == std::string::npos)
	{
		return rule_ip.substr(start, end).compare(packet_ip) != 0;
	}

	if (rule_ip.find('!') == std::string::npos && rule_ip.find('/') == std::string::npos) 
	{
		return rule_ip.compare(packet_ip) == 0;
	}

	uint32_t net_start = (net_ip & netmask);	 // first ip in subnet
	uint32_t net_end = (net_start | ~netmask); // last ip in subnet
	return ((ip >= net_start) && (ip <= net_end));
}

bool match_port(std::string rule_port, std::string packet_port)
{
	if (rule_port.compare("any") == 0 || rule_port.compare("any\n") == 0 || packet_port.compare("any") == 0 || rule_port.compare(packet_port) == 0)
	{
		return true;
	}

	if (rule_port.find('!') != std::string::npos)
	{
		std::string orgRulePort = rule_port.substr(1, rule_port.length() - 1);
		return orgRulePort.compare(packet_port) != 0;
	}
	return false;
}

uint32_t ip_to_int(std::string ip)
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

uint32_t get_net_ip(std::string net_ip, int start, int end)
{
	std::string ip = net_ip.substr(start, end);
	uint32_t result = static_cast<uint32_t>(stoul(ip));
	return result;
}

bool match_packet(std::string protocol, std::string src_ip, std::string src_port, std::string dst_ip, std::string dst_port, rule_header rule)
{
	return (match_protocol(rule.protocol, protocol)) &&
		   match_ip(rule.src_ip, src_ip) &&
		   match_ip(rule.dst_ip, dst_ip) &&
		   match_port(rule.src_port, src_port) &&
		   match_port(rule.dst_port, dst_port);
}