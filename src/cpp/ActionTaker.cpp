#include "../header/ActionTaker.h"

int getAction(std::string protocol, std::string srcIp, std::string srcPort, std::string dstIp, std::string dstPort, std::vector<RuleHeader> &rules, int mode)
{
    int action = 1;
    for (auto &rule : rules)
    {
        if ((matchProtocol(rule.protocol, protocol)) &&
            matchIp(rule.src_ip, srcIp) &&
            matchIp(rule.dst_ip, dstIp) &&
            matchPort(rule.src_port, srcPort) &&
            matchPort(rule.dst_port, dstPort))
        {
            if (rule.count == 0 || rule.match_packet_count)
            {
                if (rule.action.compare("pass") == 0)
                {
                    action = 1;
                }
                else if (rule.action.compare("alert") == 0)
                {
                    action = 2;
                }
                else if (rule.action.compare("drop") == 0)
                {
                    action = 3;
                }
                break;
            }
            else
            {
                if (rule.packet_count == 0)
                {
                    rule.start_time = clock();
                }
                rule.packet_count++;
                if (rule.packet_count >= rule.count)
                {
                    clock_t endTime = clock();
                    double passedTime = double(endTime - rule.start_time) / double(CLOCKS_PER_SEC);
                    if (passedTime <= (double)rule.time)
                    {
                        rule.match_packet_count = true;
                        if (mode == IPS_MODE)
                        {
                            action = 3;
                            break;
                        }
                    }
                    else
                    {
                        rule.packet_count = 0;
                    }
                }
            }
        }
    }

    return action;
}

void takeAction(std::string protocol, std::string srcIP, std::string dstIP, int srcPort, int dstPort, std::string action, int mode)
{
    std::string twodot = ":";
    std::string arrow = " -> ";
    std::cout << std::endl
              << "Protocol: " << protocol.c_str() << std::endl;
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
