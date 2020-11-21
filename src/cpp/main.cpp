#define APP_NAME "Magic"

#include <iostream>
#include <signal.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "../header/rule_header.h"
#include "../header/rule_reader.h"
#include "../header/action_getter.h"
#include "../header/iptables_setter.h"
#include "../header/packet_parser.h"
#include "../header/common_util.h"
#include "../header/logger.h"

vector<rule_header> rules;
int mode = IDS_MODE;

void print_app_usage()
{
	printf("Usage: %s [interface] [mode] [config]\n\n", APP_NAME);
	printf("Options: \n");
	printf("    c_mode    	  Capture mode (IPS/IDS)\n");
	printf("    r_mode    	  Running mode (NET/HOST)\n");
	printf("    config    	  Config file\n\n");
	return;
}

void handle_sigint(int sig)
{
	if (mode == IPS_MODE)
	{
		printf("\nRestoring iptables\n");
		restore_iptables();
		printf("Restored iptables\n");
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
	int nf_action = NF_ACCEPT;
	int action = get_action(protocol, src_ip, src_port, dst_ip, dst_port, rules, mode);
	if (action == ALERT)
	{
		std::string message = packet_info_to_string(protocol, src_ip, src_port, dst_ip, dst_port, false);
		printf("%s\n", message.c_str());
		log_packet_info(message);
	}
	else if (action == DROP && mode == IPS_MODE)
	{
		std::string message = packet_info_to_string(protocol, src_ip, src_port, dst_ip, dst_port, true);
		printf("%s\n", message.c_str());
		log_packet_info(message);
		nf_action = NF_DROP;
	}

	u_int32_t id;
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);
	id = ntohl(ph->packet_id);
	return nfq_set_verdict(qh, id, nf_action, 0, NULL);
}

int main(int argc, char *argv[])
{
	signal(SIGINT, handle_sigint);

	if (argc != 4)
	{
		fprintf(stderr, "Error: unrecognized command-line options\n\n");
		print_app_usage();
		exit(1);
	}

	std::string capture_mode = argv[1];
	std::string running_mode = argv[2];
	std::string config_file = argv[3];

	set_config_file_path(config_file);
	std::string rule_file_path = get_config_value("ruleFile");
	rules = get_rules(rule_file_path);

	transform(capture_mode.begin(), capture_mode.end(), capture_mode.begin(), ::tolower);
	mode = (capture_mode.compare("ips") == 0) ? IPS_MODE : IDS_MODE;

	transform(running_mode.begin(), running_mode.end(), running_mode.begin(), ::tolower);
	setup_iptables(running_mode);

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	printf("Opening library handle\n");
	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "Error during nfq_open()\n");
		exit(1);
	}

	printf("Unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "Error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("Binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "Error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &callback, NULL);
	if (!qh)
	{
		fprintf(stderr, "Error during nfq_create_queue()\n");
		exit(1);
	}

	printf("Setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		fprintf(stderr, "Can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	// para el tema del loss:   while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)

	printf("Start capturing...\n");

	while ((rv = recv(fd, buf, sizeof(buf), 0)))
	{
		nfq_handle_packet(h, buf, rv);
	}

	printf("Unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("Unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("Closing library handle\n");
	nfq_close(h);

	exit(0);
}