#include "../header/ActionTaker.h"

int get_action(std::string protocol, std::string srcIp, std::string srcPort, std::string dstIp, std::string dstPort, std::vector<RuleHeader> &rules, int mode)
{
    int action = PASS;
    for (auto &rule : rules)
    {
        if (match_packet(protocol, srcIp, srcPort, dstIp, dstPort, rule))
        {
            if (rule.count == 0 || rule.match_packet_count)
            {
                if (rule.action.compare("pass") == 0)
                {
                    action = PASS;
                }
                else if (rule.action.compare("alert") == 0)
                {
                    action = ALERT;
                }
                else if (rule.action.compare("drop") == 0)
                {
                    action = DROP;
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
                            if (rule.action.compare("pass") == 0)
                            {
                                action = PASS;
                            }
                            else if (rule.action.compare("alert") == 0)
                            {
                                action = ALERT;
                            }
                            else if (rule.action.compare("drop") == 0)
                            {
                                action = DROP;
                            }
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
