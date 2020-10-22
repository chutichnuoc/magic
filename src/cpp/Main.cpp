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

#include "../header/RuleHeader.h"
#include "../header/RuleReader.h"
#include "../header/ActionTaker.h"
#include "../header/IptablesSetup.h"
#include "../header/ConfigReader.h"
#include "../header/ProtocolHandler.h"
#include "../header/CommonUtil.h"

vector<RuleHeader> rules;
int mode = IDS_MODE;

void print_app_usage()
{
	cout << "Usage: " << APP_NAME << " [interface] [mode] [config]" << endl << endl;
	cout << "Options: " << endl;
	cout << "    interface    Listen on <interface> for packets" << endl;
	cout << "    mode    	  Capture mode" << endl;
	cout << "    config    	  Config file" << endl;
	cout << endl;
	return;
}

void handle_sigint(int sig)
{
	if (mode == IPS_MODE)
	{
		std::cout << "Restoring iptables" << endl;
		restore_iptables();
		std::cout << "Restored iptables" << endl;
	}
	exit(0);
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	uint8_t *packet = NULL;
	nfq_get_payload(nfa, &packet);

	std::string protocol("ip");
	std::string src_ip("any");
	std::string dst_ip("any");
	std::string src_port("any");
	std::string dst_port("any");

	handle_ip(packet, &protocol, &src_ip, &src_port, &dst_ip, &dst_port);
	int nfAction = NF_ACCEPT;
	int action = getAction(protocol, src_ip, src_port, dst_ip, dst_port, rules, mode);
	if (action == ALERT)
	{
		cout << packet_info_to_string(protocol, src_ip, src_port, dst_ip, dst_port, false) << endl;
	}
	else if (action == DROP)
	{
		cout << packet_info_to_string(protocol, src_ip, src_port, dst_ip, dst_port, true) << endl;
		nfAction = NF_DROP;
	}

	cout << get_cpu_usage() << endl;

	u_int32_t id;
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);
	return nfq_set_verdict(qh, id, nfAction, 0, NULL);
}

int main(int argc, char *argv[])
{
	signal(SIGINT, handle_sigint);

	if (argc != 4)
	{
		cout << stderr << "error: unrecognized command-line options" << endl << endl;
		print_app_usage();
		exit(1);
	}

	string interface = argv[1];
	string running_mode = argv[2];
	string config_file = argv[3];

	set_config_File_path(config_file);
	setup_iptables(interface);
	string rule_file_path = get_config_value("ruleFile");
	rules = get_rules(rule_file_path);
	mode = (running_mode.compare("IPS") == 0) ? IPS_MODE : IDS_MODE;

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	// printf("opening library handle\n");
	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	// printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	// printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	// printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &callback, NULL);
	if (!qh)
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	// printf("setting copy_packet mode\n");
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

	// printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	// printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}