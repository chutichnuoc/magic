#define APP_NAME "Magic"

#include "stdlib.h"
#include "PcapLiveDeviceList.h"
#include "PcapFileDevice.h"
#include <iostream>
#include <bits/stdc++.h>
#include <sys/wait.h>
#include <stdio.h>
#include <signal.h>

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "../sniff_header/sniff_ip.h"

#include "../header/RuleHeader.h"
#include "../header/RuleReader.h"
#include "../header/ActionTaker.h"
#include "../header/IptablesSetup.h"
#include "../header/ConfigReader.h"
#include "../header/ProtocolHandler.h"

vector<RuleHeader> rules;
int mode = IDS_MODE;

std::string exec(const char *cmd)
{
	std::array<char, 128> buffer;
	std::string result;
	std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
	if (!pipe)
	{
		throw std::runtime_error("popen() failed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
	{
		result += buffer.data();
	}
	return result;
}

void printAppUsage()
{
	cout << "Usage: " << APP_NAME << " [interface] [mode] [config]" << endl
		 << endl;
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

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	uint8_t *packet = NULL;
	nfq_get_payload(nfa, &packet);

	const struct sniff_ip *ip; /* The IP header */
	int size_ip;
	/* define/compute ip header offset */
	ip = (struct sniff_ip *)(packet);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20)
	{
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return 0;
	}
	std::string srcIp("any");
	std::string dstIp("any");

	srcIp = inet_ntoa(ip->ip_src);
	dstIp = inet_ntoa(ip->ip_dst);

	std::string srcPort("any");
	std::string dstPort("any");

	std::string protocol("ip");

	/* determine protocol */
	switch (ip->ip_p)
	{
	case IPPROTO_TCP:
		protocol = "tcp";
		handle_tcp(packet, size_ip, &srcPort, &dstPort);
		break;
	case IPPROTO_UDP:
		protocol = "udp";
		handle_udp(packet, size_ip, &srcPort, &dstPort);
		break;
	case IPPROTO_ICMP:
		protocol = "icmp";
		srcPort = "any";
		dstPort = "any";
		break;
	}
	int nfAction = NF_ACCEPT;
	std::cout << rules.size() << std::endl;
	int action = getAction(protocol, srcIp, srcPort, dstIp, dstPort, rules, mode);
	if (action == 1)
	{
		// pass
	}
	else if (action == 2)
	{
		// log
		std::string twodot = ":";
		std::string arrow = " -> ";
		std::cout << std::endl
				  << "Protocol: " << protocol.c_str() << std::endl;
		if (protocol.compare("icmp") == 0)
		{
			std::cout << srcIp << " -> " << dstIp << std::endl;
		}
		else
		{
			std::cout << srcIp << ":" << srcPort << " -> " << dstIp << ":" << dstPort << std::endl;
		}
	}
	else if (action == 3)
	{
		std::string twodot = ":";
		std::string arrow = " -> ";
		std::cout << std::endl
				  << "Protocol: " << protocol.c_str() << std::endl;
		if (protocol.compare("icmp") == 0)
		{
			std::cout << srcIp << " -> " << dstIp << " (drop)" << std::endl;
		}
		else
		{
			std::cout << srcIp << ":" << srcPort << " -> " << dstIp << ":" << dstPort << " (drop)"  << std::endl;
		}
		nfAction = NF_DROP;
	}

	cout << exec("grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage \"%\"}'") << endl;

	u_int32_t id;
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);
	return nfq_set_verdict(qh, id, nfAction, 0, NULL);
}

int main(int argc, char *argv[])
{
	signal(SIGINT, handleSigint);

	if (argc != 4)
	{
		cout << stderr << "error: unrecognized command-line options" << endl
			 << endl;
		printAppUsage();
		exit(EXIT_FAILURE);
	}

	string interface = argv[1];
	string runningMode = argv[2];
	string configFile = argv[3];

	setConfigFilePath(configFile);
	setupIptables(interface);
	string ruleFilePath = getConfigValue("ruleFile");
	rules = getRules(ruleFilePath);
	mode = (runningMode.compare("IPS") == 0) ? IPS_MODE : IDS_MODE;

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh)
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	// para el tema del loss:   while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)

	while ((rv = recv(fd, buf, sizeof(buf), 0)))
	{
		nfq_handle_packet(h, buf, rv);
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}