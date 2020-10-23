#include "../header/packet_parser.h"

void handle_tcp(const u_char *packet, int size_ip, std::string *src_port, std::string *dst_port)
{
	const struct sniff_tcp *tcp;
	int size_tcp;
	tcp = (struct sniff_tcp *)(packet + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20)
	{
		printf("   * Invalid TCP header length:  %d bytes", size_tcp);
		return;
	}

	*src_port = std::to_string(ntohs(tcp->th_sport));
	*dst_port = std::to_string(ntohs(tcp->th_dport));
}

void handle_udp(const u_char *packet, int size_ip, std::string *src_port, std::string *dst_port)
{
	const struct sniff_udp *udp;
	int size_udp;
	udp = (struct sniff_udp *)(packet + size_ip);
	size_udp = udp->uh_ulen * 4;
	if (size_udp < 20)
	{
		printf("   * Invalid UDP header length:  %d bytes", size_udp);
		return;
	}

	*src_port = std::to_string(ntohs(udp->uh_sport));
	*dst_port = std::to_string(ntohs(udp->uh_dport));
}

void handle_ip(const u_char *packet, std::string *protocol, std::string *src_ip, std::string *src_port, std::string *dst_ip, std::string *dst_port)
{
	const struct sniff_ip *ip;
	int size_ip;
	ip = (struct sniff_ip *)(packet);
	size_ip = IP_HL(ip) * 4;
	if (size_ip < 20)
	{
		printf("   * Invalid IP header length:  %d bytes", size_ip);
		return;
	}

	*src_ip = inet_ntoa(ip->ip_src);
	*dst_ip = inet_ntoa(ip->ip_dst);

	switch (ip->ip_p)
	{
	case IPPROTO_TCP:
		*protocol = "tcp";
		handle_tcp(packet, size_ip, src_port, dst_port);
		break;
	case IPPROTO_UDP:
		*protocol = "udp";
		handle_udp(packet, size_ip, src_port, dst_port);
		break;
	case IPPROTO_ICMP:
		*protocol = "icmp";
		*src_port = "any";
		*dst_port = "any";
		break;
	}
}
