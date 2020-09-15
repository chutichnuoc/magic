#include "ActionTaker.h"
#include "Logger.h"

void takeAction(pcpp::Packet parsedPacket, std::vector<RuleHeader> &rules)
{
    std::string srcMac("any");
    std::string dstMac("any");
    std::string srcIP("any");
    std::string dstIP("any");
    int srcPort = 0;
    int dstPort = 0;
    std::string networkProtocol("unknown");
    std::string transportProtocol("unknown");
    std::string applicationProtocol("unknown");
    std::string action("pass");

    for (pcpp::Layer *curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
    {
        switch (curLayer->getProtocol())
        {
        case pcpp::Ethernet:
            parseEthLayer(parsedPacket, &srcMac, &dstMac);
            break;
        case pcpp::IPv4:
            networkProtocol = "IP";
            parseIpv4Layer(parsedPacket, &srcIP, &dstIP);
            break;
        case pcpp::ICMP:
            networkProtocol = "ICMP";
            //printIcmpLayer(parsedPacket);
            break;
        case pcpp::TCP:
            transportProtocol = "TCP";
            parseTcpLayer(parsedPacket, &srcPort, &dstPort);
            break;
        case pcpp::UDP:
            transportProtocol = "UDP";
            parseUdpLayer(parsedPacket, &srcPort, &dstPort);
            break;
        case pcpp::DNS:
            applicationProtocol = "DNS";
            break;
        case pcpp::DHCP:
            applicationProtocol = "DHCP";
            break;
        case pcpp::HTTP:
            applicationProtocol = "HTTP";
            //printHttpLayer(parsedPacket);
            break;
        case pcpp::SSL:
            applicationProtocol = "SSL";
            //printSSLLayer(parsedPacket);
            break;
        case pcpp::GenericPayload:
            applicationProtocol = "GenericPayload";
            // printPayload(parsedPacket);
            break;
        case pcpp::UnknownProtocol:
            std::cout << "Unknown protocol" << std::endl;
            break;
        }
    }

    for (auto &rule : rules)
    {
        if ((matchProtocol(rule.protocol, networkProtocol.c_str()) ||
             matchProtocol(rule.protocol, transportProtocol.c_str()) ||
             matchProtocol(rule.protocol, applicationProtocol.c_str())) &&
            matchIp(rule.srcIp, srcIP.c_str()) &&
            matchIp(rule.dstIp, dstIP.c_str()) &&
            matchPort(rule.srcPort, to_string(srcPort)) &&
            matchPort(rule.dstPort, to_string(dstPort)))
        {
            if (rule.count == 0 || rule.matchPacketCount)
            {
                action = rule.action;
                break;
            }
            else {
                if (rule.packetCount == 0) {
                    rule.startTime = clock();
                }
                rule.packetCount++;
                if (rule.packetCount >= rule.count) {
                    clock_t endTime = clock();
                    double passedTime = double(endTime - rule.startTime) / double(CLOCKS_PER_SEC);
                    if (passedTime <= (double) rule.time) {
                        rule.matchPacketCount = true;
                    }
                    else {
                        rule.packetCount = 0;
                    }
                }
            }
        }
    }

    std::cout << std::endl;
    // std::cout << "Scr MAC: " << srcMac.c_str() << endl;
    // std::cout << "Dst MAC: " << dstMac.c_str() << endl;
    std::cout << "Network Protocol: " << networkProtocol.c_str() << std::endl;
    std::cout << "Transport Protocol: " << transportProtocol.c_str() << std::endl;
    std::cout << "Application Protocol: " << applicationProtocol.c_str() << std::endl;
    std::cout << "Source: " << srcIP.c_str() << ":" << srcPort << std::endl;
    std::cout << "Destination: " << dstIP.c_str() << ":" << dstPort << std::endl;
    std::cout << "Action: " << action << std::endl;
    // std::cout << "Size: " << packet->getRawDataLen() << std::endl;

    std::cout << std::endl;

    if (action.compare("alert") == 0) {
        std::string twodot = ":";
        logPacketInfo(srcIP.c_str() + twodot + std::to_string(srcPort) + " -> " + dstIP.c_str() + twodot + std::to_string(dstPort));
    }
}