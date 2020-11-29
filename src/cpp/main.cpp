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

struct queueStuff
{
	int queue;
	int maxqueue;
	queueStuff(int i, int m) : queue(i), maxqueue(m) {}
};

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

	int action = get_action(protocol, src_ip, src_port, dst_ip, dst_port, rules);
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
	// queueStuff *p = (queueStuff *)data;
	// printf("Queue %d\n ", p->queue);
	return nfq_set_verdict(qh, id, nf_action, 0, NULL);
}

void *process_queue(void *q)
{
	queueStuff *qs = (queueStuff *)q;

	struct nfq_handle *nfq_handle = NULL;
	nfq_handle = nfq_open();

	if (!nfq_handle)
	{
		perror("nfq_open");
		exit(1);
	}

	printf("Unbinding...\n");
	if (nfq_unbind_pf(nfq_handle, AF_INET) < 0)
	{
		perror("nfq_unbind_pf");
		exit(1);
	}

	printf("Binding to process IP packets\n");
	if (nfq_bind_pf(nfq_handle, AF_INET) < 0)
	{
		perror("nfq_bind_pf");
		exit(1);
	}
	printf("Creating netfilter handle %d\n", qs->queue);
	struct nfq_q_handle *my_queue = NULL;
	struct nfnl_handle *netlink_handle = NULL;

	int fd = -1;
	ssize_t res;
	char buf[4096];

	printf("Installing queue %d\n", qs->queue);

	if (!(my_queue = nfq_create_queue(nfq_handle, qs->queue, &callback, q)))
	{
		perror("nfq_create_queue");
		exit(1);
	}

	printf("Myqueue for %d is %p\n", qs->queue, my_queue);
	fflush(stdout);

	// Turn on packet copy mode ... NOTE: only copy_packet really works
	int what_to_copy = NFQNL_COPY_PACKET;
	// int what_to_copy = NFQNL_COPY_META;

	// A little more than the standard header...
	// int size_to_copy = sizeof(ip) + sizeof(tcphdr) + 10;
	int size_to_copy = 10000;

	if (nfq_set_mode(my_queue, what_to_copy, size_to_copy) < 0)
	{
		perror("nfq_set_mode");
		exit(1);
	}

	printf("Set mode for %d\n", qs->queue);
	fflush(stdout);

	if (nfq_set_queue_maxlen(my_queue, qs->maxqueue) < 0)
	{
		printf("Couldn't set queue max len to %d.\n", qs->maxqueue);
	}
	else
	{
		printf("Set queue length to %d packets\n", qs->maxqueue);
		fflush(stdout);
	}

	netlink_handle = nfq_nfnlh(nfq_handle);

	if (!netlink_handle)
	{
		perror("nfq_nfnlh");
		exit(1);
	}

	printf("Got netlink handle for %d\n", qs->queue);
	fflush(stdout);

	nfnl_rcvbufsiz(netlink_handle, qs->maxqueue * 1500);

	printf("Set recv buffer size to %d\n", qs->maxqueue * 1500);
	fflush(stdout);

	fd = nfnl_fd(netlink_handle);

	printf("Queue #%d: fd = %d\n", qs->queue, fd);
	fflush(stdout);

	int opt = 1;
	setsockopt(fd, SOL_NETLINK, NETLINK_BROADCAST_SEND_ERROR, &opt, sizeof(int));
	setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int));

	printf("Ignoring buffer overflows...folklore\n");
	fflush(stdout);

	while ((res = recv(fd, buf, sizeof(buf), 0)) && res >= 0)
	{
		nfq_handle_packet(nfq_handle, buf, res);
	}

	perror("recv");

	nfq_destroy_queue(my_queue);
	nfq_close(nfq_handle);
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

	thread th(set_cpu_last_second);

	pthread_t threads[100];

	int num_queues = 3;
	int max_queue = 10000;
	for (int i = 0; i < num_queues; i++)
	{
		pthread_create(&threads[i], NULL, process_queue, new queueStuff(i, max_queue));
		// sleep(1);
	}

	for (int i = 0; i < num_queues; i++)
	{
		pthread_join(threads[i], NULL);
	}
	th.join();

	return 0;
}