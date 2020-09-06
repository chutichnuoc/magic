#include "Parser.h"

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

void printHttpLayer(pcpp::Packet parsedPacket)
{
	pcpp::HttpRequestLayer *httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
	if (httpRequestLayer == NULL)
	{
		printf("Something went wrong, couldn't find HTTP request layer\n");
		return;
	}

	// print HTTP method and URI. Both appear in the first line of the HTTP request
	printf("\nHTTP method: %s\n", printHttpMethod(httpRequestLayer->getFirstLine()->getMethod()).c_str());
	//printf("HTTP URI: %s\n", httpRequestLayer->getFirstLine()->getUri().c_str());

	// print values of the following HTTP field: Host, User-Agent and Cookie
	//printf("HTTP host: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_HOST_FIELD)->getFieldValue().c_str());
	printf("HTTP user-agent: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_USER_AGENT_FIELD)->getFieldValue().c_str());
	//printf("HTTP cookie: %s\n", httpRequestLayer->getFieldByName(PCPP_HTTP_COOKIE_FIELD)->getFieldValue().c_str());

	// print the full URL of this request
	printf("HTTP full URL: %s\n", httpRequestLayer->getUrl().c_str());
}

void printSSLLayer(pcpp::Packet parsedPacket)
{
	pcpp::SSLLayer *sSLLayer = parsedPacket.getLayerOfType<pcpp::SSLLayer>();
	if (sSLLayer == NULL)
	{
		printf("Something went wrong, couldn't find SSL request layer\n");
		return;
	}

	printf("\nRecord type: %d\n", sSLLayer->getRecordLayer()->recordType);
}

std::string printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod)
{
	switch (httpMethod)
	{
	case pcpp::HttpRequestLayer::HttpGET:
		return "GET";
	case pcpp::HttpRequestLayer::HttpPOST:
		return "POST";
	default:
		return "Other";
	}
}

void printPayload(pcpp::Packet parsedPacket)
{
	pcpp::PayloadLayer *payloadLayer = parsedPacket.getLayerOfType<pcpp::PayloadLayer>();
	
	std::cout << "getPayloadLen(): " << payloadLayer->getPayloadLen() << std::endl;
	std::cout << "getPayload(): " <<  static_cast<void*>(payloadLayer->getPayload()) << std::endl;
}