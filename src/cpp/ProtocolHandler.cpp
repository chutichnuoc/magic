#include "../header/ProtocolHandler.h"

void handle_tcp(const u_char *packet, int size_ip, std::string *srcPort, std::string *dstPort)
{
	const struct sniff_tcp *tcp; /* The TCP header */
	int size_tcp;
	tcp = (struct sniff_tcp *)(packet + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20)
	{
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	int src_port = ntohs(tcp->th_sport);
	int dst_port = ntohs(tcp->th_dport);

	*srcPort = std::to_string(src_port);
	*dstPort = std::to_string(dst_port);
}

void handle_udp(const u_char *packet, int size_ip, std::string *srcPort, std::string *dstPort)
{
	const struct sniff_udp *udp; /* The UDP header */
	int size_udp;
	udp = (struct sniff_udp *)(packet + size_ip);
	size_udp = udp->uh_ulen*4;
	if (size_udp < 20) {
		printf("   * Invalid UDP header length: %u bytes\n", size_udp);
		return;
	}

	int src_port = ntohs(udp->uh_sport);
	int dst_port = ntohs(udp->uh_dport);

	*srcPort = std::to_string(src_port);
	*dstPort = std::to_string(dst_port);
}
