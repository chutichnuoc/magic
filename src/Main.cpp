#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include <iostream>
#include <bits/stdc++.h>
#include "RuleHeader.h"
#include "RuleReader.h"
#include <sys/wait.h>
#include "ActionTaker.h"
#include "IptablesSetup.h"

vector<RuleHeader> Rules;
int mode = 1;

void setupIptables()
{
	clearIptables();
	for (auto &rule : Rules)
	{
		addRuleToIptables(rule);
	}
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
	takeAction(packet, Rules, mode);
}

int main(int argc, char *argv[])
{
	string filePath = "/home/chutichnuoc/ppp_ids/rules/test.rules";
	Rules = getRules(filePath);

	std::cout << "Choose mode: " << endl;
	std::cout << "1. IDS" << endl;
	std::cout << "2. IPS" << endl;
	std::cout << endl;

	std::cout << "Choose mode: ";
	cin >> mode;
	if (mode == 1)
	{
	}
	else if (mode == 2)
	{
		setupIptables();
	}

	std::cout << "List devices:" << endl;
	std::cout << endl;

	auto deviceList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	for (auto &device : deviceList)
	{
		std::cout << "Device " << device->getName() << " " << device->getIPv4Address().toString().c_str() << endl;
	}

	int deviceNo = 1;
	std::cout << endl;
	std::cout << "Choose a divece to capture: ";
	cin >> deviceNo;
	pcpp::PcapLiveDevice *device = deviceList[deviceNo - 1];

	if (device == NULL)
	{
		std::cout << "Cannot find interface with name of '" << deviceList[deviceNo - 1]->getName() << "'" << endl;
		exit(1);
	}

	printDeviceInfo(device);

	if (!device->open())
	{
		std::cout << "Cannot open device" << endl;
		exit(1);
	}

	std::cout << endl;
	std::cout << "Starting async capture..." << endl;

	device->startCapture(onPacketArrives, 0);
	PCAP_SLEEP(-1);
	device->stopCapture();
	device->close();

	std::cout << "Done!" << endl;
}