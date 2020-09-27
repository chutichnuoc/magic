#include "../header/Parser.h"

void parseEthLayer(pcpp::Packet parsedPacket, std::string *srcMac, std::string *dstMac)
{
	pcpp::EthLayer *ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
	if (ethernetLayer == NULL)
	{
		printf("Something went wrong, couldn't find Ethernet layer\n");
		return;
	}

	*srcMac = ethernetLayer->getSourceMac().toString().c_str();
	*dstMac = ethernetLayer->getDestMac().toString().c_str();
}

void parseIpv4Layer(pcpp::Packet parsedPacket, std::string *srcIP, std::string *dstIP)
{
	pcpp::IPv4Layer *ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ipLayer == NULL)
	{
		printf("Something went wrong, couldn't find IPv4 layer\n");
		return;
	}

	*srcIP = ipLayer->getSrcIpAddress().toString().c_str();
	*dstIP = ipLayer->getDstIpAddress().toString().c_str();
}

void printIcmpLayer(pcpp::Packet parsedPacket)
{
	pcpp::IcmpLayer *icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
	if (icmpLayer == NULL)
	{
		printf("Something went wrong, couldn't find ICMP layer\n");
		return;
	}

	// printf ICMP code and type
	printf("\nIcmp code: %d\n", (int)ntohs(icmpLayer->getIcmpHeader()->code));
	printf("Icmp type: %d\n", (int)ntohs(icmpLayer->getIcmpHeader()->type));
}

void parseTcpLayer(pcpp::Packet parsedPacket, int *srcPort, int *dstPort)
{
	pcpp::TcpLayer *tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
	if (tcpLayer == NULL)
	{
		printf("Something went wrong, couldn't find TCP layer\n");
		return;
	}

	*srcPort = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
	*dstPort = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
}

void parseUdpLayer(pcpp::Packet parsedPacket, int *srcPort, int *dstPort)
{
	pcpp::UdpLayer *udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
	if (udpLayer == NULL)
	{
		printf("Something went wrong, couldn't find UDP layer\n");
		return;
	}

	*srcPort = (int)ntohs(udpLayer->getUdpHeader()->portSrc);
	*dstPort = (int)ntohs(udpLayer->getUdpHeader()->portDst);
}
