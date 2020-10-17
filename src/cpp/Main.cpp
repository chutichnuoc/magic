#define APP_NAME "Magic"

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
#include "../header/ConfigReader.h"

vector<RuleHeader> rules;
int mode = IDS_MODE;

void printAppUsage()
{
	cout << "Usage: " << APP_NAME << " [interface] [mode] [config]" << endl << endl;
	cout << "Options: " << endl;
	cout << "    interface    Listen on <interface> for packets" << endl;
	cout << "    mode    	  Capture mode" << endl;
	cout << "    config    	  Config file" << endl;
	cout << endl;
	return;
}

void handleSigint(int sig)
{
	if (mode == IPS_MODE)
	{
		std::cout << "Restoring iptables" << endl;
		restoreIptalbes();
		std::cout << "Restored iptables" << endl;
	}
	exit(EXIT_SUCCESS);
}

static void onPacketArrives(pcpp::RawPacket *packet, pcpp::PcapLiveDevice *dev, void *cookie)
{
	pcpp::Packet parsedPacket(packet);
	handlePacket(packet, rules, mode);
}

int main(int argc, char *argv[])
{
	signal(SIGINT, handleSigint);

	if (argc != 4)
	{
		cout << stderr << "error: unrecognized command-line options" << endl << endl;
		printAppUsage();
		exit(EXIT_FAILURE);
	}

	string interface = argv[1];
	string runningMode = argv[2];
	string configFile = argv[3];

	setConfigFilePath(configFile);

	string ruleFilePath = getConfigValue("ruleFile");
	rules = getRules(ruleFilePath);

	mode = (runningMode.compare("IPS") == 0) ? IPS_MODE : IDS_MODE;
	if (mode == IPS_MODE)
	{
		setupIptables(rules);
	}

	pcpp::PcapLiveDevice *device = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(interface);
	if (device == NULL)
	{
		std::cout << "Cannot find interface with name of '" << interface << "'" << endl;
		exit(EXIT_FAILURE);
	}

	if (!device->open())
	{
		std::cout << "Cannot open device" << endl;
		exit(EXIT_FAILURE);
	}

	std::cout << "Starting async capture..." << endl;

	device->startCapture(onPacketArrives, 0);
	PCAP_SLEEP(-1);
	device->stopCapture();
	device->close();
}