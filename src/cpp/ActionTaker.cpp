#include "../header/ActionTaker.h"

void handlePacket(pcpp::Packet parsedPacket, std::vector<RuleHeader> &rules, int mode)
{
    std::string srcIP("any");
    std::string dstIP("any");
    int srcPort = 0;
    int dstPort = 0;
    std::string networkProtocol("unknown");
    std::string transportProtocol("unknown");
    std::string action("pass");

    for (pcpp::Layer *curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
    {
        switch (curLayer->getProtocol())
        {
        case pcpp::IPv4:
            networkProtocol = "IP";
            parseIpv4Layer(parsedPacket, &srcIP, &dstIP);
            break;
        case pcpp::ICMP:
            networkProtocol = "ICMP";
            break;
        case pcpp::TCP:
            transportProtocol = "TCP";
            parseTcpLayer(parsedPacket, &srcPort, &dstPort);
            break;
        case pcpp::UDP:
            transportProtocol = "UDP";
            parseUdpLayer(parsedPacket, &srcPort, &dstPort);
            break;
        }
    }

    for (auto &rule : rules)
    {
        if ((matchProtocol(rule.protocol, networkProtocol.c_str()) ||
             matchProtocol(rule.protocol, transportProtocol.c_str())) &&
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
            else
            {
                if (rule.packetCount == 0)
                {
                    rule.startTime = clock();
                }
                rule.packetCount++;
                if (rule.packetCount >= rule.count)
                {
                    clock_t endTime = clock();
                    double passedTime = double(endTime - rule.startTime) / double(CLOCKS_PER_SEC);
                    if (passedTime <= (double)rule.time)
                    {
                        rule.matchPacketCount = true;
                        if (mode == IPS_MODE)
                        {
                            addRuleToIptables(rule);
                        }
                    }
                    else
                    {
                        rule.packetCount = 0;
                    }
                }
            }
        }
    }

    if (networkProtocol.compare("unknown") == 0)
    {
        return;
    }
    if (networkProtocol.compare("ICMP") == 0)
    {
        takeAction(networkProtocol, srcIP, dstIP, srcPort, dstPort, action, mode);
    }
    else
    {
        takeAction(transportProtocol, srcIP, dstIP, srcPort, dstPort, action, mode);
    }
}

void takeAction(std::string protocol, std::string srcIP, std::string dstIP, int srcPort, int dstPort, std::string action, int mode)
{
    std::string twodot = ":";
    std::string arrow = " -> ";
    std::cout << std::endl << "Protocol: " << protocol.c_str() << std::endl;
    if (protocol.compare("ICMP") == 0)
    {
        std::cout << srcIP.c_str() << " -> " << dstIP.c_str() << std::endl;
    }
    else
    {
        std::cout << srcIP.c_str() << ":" << srcPort << " -> " << dstIP.c_str() << ":" << dstPort << std::endl;
    }

    if (action.compare("pass") == 0)
    {
        std::cout << "Action: " << action << std::endl;
    }
    else if (action.compare("alert") == 0)
    {
        if (protocol.compare("ICMP") == 0)
        {
            logPacketInfo(srcIP.c_str() + arrow + dstIP.c_str());
        }
        else
        {
            logPacketInfo(srcIP.c_str() + twodot + std::to_string(srcPort) + arrow + dstIP.c_str() + twodot + std::to_string(dstPort));
        }
        std::cout << "Action: " << action << std::endl;
    }
    else if (action.compare("drop") == 0 && mode == IPS_MODE)
    {
        if (protocol.compare("ICMP") == 0)
        {
            logPacketInfo(srcIP.c_str() + arrow + dstIP.c_str() + " (dropped)");
        }
        else
        {
            logPacketInfo(srcIP.c_str() + twodot + std::to_string(srcPort) + arrow + dstIP.c_str() + twodot + std::to_string(dstPort) + " (dropped)");
        }
        std::cout << "Action: " << action << std::endl;
    }
}