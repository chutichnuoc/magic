#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "PlatformSpecificUtils.h"
#include "PcapFileDevice.h"
#include "Parser.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include "RuleHeader.h"
#include "Matcher.h"

using namespace std;
using namespace pcpp;

vector<RuleHeader> Rules;

void getRules(string filePath)
{
	ifstream infile(filePath);
	string line;
	while (getline(infile, line))
	{
		istringstream iss(line);
		string action, protocol, srcIp, srcPort, flow, dstIp, dstPort;
		if (!(iss >> action >> protocol >> srcIp >> srcPort >> flow >> dstIp >> dstPort))
		{
			iss.clear();
			break;
		}
		RuleHeader rule(action, protocol, srcIp, srcPort, dstIp, dstPort);
		Rules.push_back(rule);
	}
	infile.close();
}

void printDeviceInfo(pcpp::PcapLiveDevice *dev)
{
	std::cout << "Interface info:" << endl;
	std::cout << "   Interface name:        " << dev->getName() << endl;
	std::cout << "   Interface description: " << dev->getDesc() << endl;
	std::cout << "   MAC address:           " << dev->getMacAddress().toString().c_str() << endl;
	std::cout << "   Default gateway:       " << dev->getDefaultGateway().toString().c_str() << endl;
	std::cout << "   Interface MTU:         " << dev->getMtu() << endl;
	if (dev->getDnsServers().size() > 0)
	{
		std::cout << "   DNS server:            " << dev->getDnsServers().at(0).toString().c_str() << endl;
	}
}

static void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie)
{
	// parsed the raw packet
	pcpp::Packet parsedPacket(packet);

	std::string srcMac("any");
	std::string dstMac("any");
	std::string srcIP("any");
	std::string dstIP("any");
	int srcPort = 0;
	int dstPort = 0;
	std::string networkProtocol("unknown");
	std::string transportProtocol("unknown");
	std::string applicationProtocol("unknown");
	std::string action("pass");

	for (pcpp::Layer *curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
	{
		switch (curLayer->getProtocol())
		{
		case pcpp::Ethernet:
			parseEthLayer(parsedPacket, &srcMac, &dstMac);
			break;
		case pcpp::IPv4:
			networkProtocol = "IP";
			parseIpv4Layer(parsedPacket, &srcIP, &dstIP);
			break;
		case pcpp::ICMP:
			networkProtocol = "ICMP";
			printIcmpLayer(parsedPacket);
			break;
		case pcpp::TCP:
			transportProtocol = "TCP";
			parseTcpLayer(parsedPacket, &srcPort, &dstPort);
			break;
		case pcpp::UDP:
			transportProtocol = "UDP";
			parseUdpLayer(parsedPacket, &srcPort, &dstPort);
			break;
		case pcpp::DNS:
			applicationProtocol = "DNS";
			break;
		case pcpp::DHCP:
			applicationProtocol = "DHCP";
			break;
		case pcpp::HTTP:
		case pcpp::HTTPRequest:
		case pcpp::HTTPResponse:
			applicationProtocol = "HTTP";
			//printHttpLayer(parsedPacket);
			break;
		case pcpp::SSL:
			applicationProtocol = "HTTP";
			//printSSLLayer(parsedPacket);
			break;
			// default:
			// 	return "Unknown";
		case pcpp::GenericPayload:
			printPayload(parsedPacket);
			break;
		}
	}
	std::cout << endl;
	// std::cout << "Scr MAC: " << srcMac.c_str() << endl;
	// std::cout << "Dst MAC: " << dstMac.c_str() << endl;
	std::cout << "Network Protocol: " << networkProtocol.c_str() << endl;
	std::cout << "Transport Protocol: " << transportProtocol.c_str() << endl;
	std::cout << "Application Protocol: " << applicationProtocol.c_str() << endl;
	std::cout << "Scr IP: " << srcIP.c_str() << ":" << srcPort << endl;
	std::cout << "Dst IP: " << dstIP.c_str() << ":" << dstPort << endl;

	for (auto &rule : Rules)
	{
		if ((matchProtocol(rule.protocol, networkProtocol.c_str()) ||
			 matchProtocol(rule.protocol, transportProtocol.c_str()) ||
			 matchProtocol(rule.protocol, applicationProtocol.c_str())) &&
			matchIp(rule.srcIp, srcIP.c_str()) &&
			matchIp(rule.dstIp, dstIP.c_str()) &&
			matchPort(rule.srcPort, to_string(srcPort)) &&
			matchPort(rule.dstPort, to_string(dstPort)))
		{
			action = rule.action;
			break;
		}
	}
	std::cout << "Action: " << action << endl;

	std::cout << endl;
}

int main(int argc, char *argv[])
{
	string filePath = "/home/chutichnuoc/ppp_ids/rules/test.rules";
	getRules(filePath);

	std::cout << "List devices:" << endl
		 << endl;
	for (int i = 0; i < PcapLiveDeviceList::getInstance().getPcapLiveDevicesList().size(); i++)
	{
		std::cout << "Device no " << i + 1 << " " << PcapLiveDeviceList::getInstance().getPcapLiveDevicesList()[i]->getName() << endl;
	}
	int deviceNo = 1;
	std::cout << endl
		 << "Choose a divece to capture: ";
	cin >> deviceNo;
	PcapLiveDevice *dev = PcapLiveDeviceList::getInstance().getPcapLiveDevicesList()[deviceNo - 1];

	if (dev == NULL)
	{
		std::cout << "Cannot find interface with name of '" << PcapLiveDeviceList::getInstance().getPcapLiveDevicesList()[deviceNo - 1]->getName() << "'" << endl;
		exit(1);
	}

	printDeviceInfo(dev);

	if (!dev->open())
	{
		std::cout << "Cannot open device" << endl;
		exit(1);
	}

	std::cout << endl
		 << "Starting async capture..." << endl;

	// start capture in async mode. Give a callback function to call to whenever a packet is captured and the stats object as the cookie
	dev->startCapture(onPacketArrives, 0);

	// sleep for 5 seconds in main thread, in the meantime packets are captured in the async thread
	PCAP_SLEEP(5);

	// stop capturing packets
	dev->stopCapture();

	// close the device before application ends
	dev->close();

	std::cout << "Done!" << endl;
}