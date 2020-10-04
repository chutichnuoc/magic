#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include <iostream>
#include <bits/stdc++.h>
#include <sys/wait.h>
#include <stdio.h>
#include <signal.h>
#include "../header/RuleHeader.h"
#include "../header/RuleReader.h"
#include "../header/ActionTaker.h"
#include "../header/IptablesSetup.h"

vector<RuleHeader> rules;
int mode = IDS_MODE;

void handle_sigint(int sig)
{
	if (mode == IPS_MODE)
	{
		std::cout << "Restoring iptables" << endl;
		restoreIptalbes();
		std::cout << "Restored iptables" << endl;
	}
	exit(0);
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
	pcpp::Packet parsedPacket(packet);
	handlePacket(packet, rules, mode);
}

static int getRunningMode()
{
	int mode;
	std::cout << "Running mode: " << endl;
	std::cout << "1. IDS" << endl;
	std::cout << "2. IPS" << endl;
	std::cout << "Choose mode: ";
	cin >> mode;
	return mode;
}

int main(int argc, char *argv[])
{
	signal(SIGINT, handle_sigint);
	string filePath = "/home/chutichnuoc/ppp_ids/rules/test.rules";
	rules = getRules(filePath);

	mode = getRunningMode();
	if (mode == IPS_MODE)
	{
		setupIptables(rules);
	}

	std::cout << endl
			  << "List devices:" << endl;

	auto deviceList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
	for (auto &device : deviceList)
	{
		std::cout << "Device " << device->getName() << " " << device->getIPv4Address().toString().c_str() << endl;
	}

	int deviceNo = 1;
	std::cout << "Choose a divece to capture: ";
	cin >> deviceNo;
	pcpp::PcapLiveDevice *device = deviceList[deviceNo - 1];

	if (device == NULL)
	{
		std::cout << "Cannot find interface with name of '" << deviceList[deviceNo - 1]->getName() << "'" << endl;
		exit(1);
	}

	if (!device->open())
	{
		std::cout << "Cannot open device" << endl;
		exit(1);
	}

	printDeviceInfo(device);

	std::cout << endl;
	std::cout << "Starting async capture..." << endl;

	device->startCapture(onPacketArrives, 0);
	PCAP_SLEEP(-1);
	device->stopCapture();
	device->close();
}