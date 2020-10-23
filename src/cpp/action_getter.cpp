#include "../header/action_getter.h"

int rule_action_to_app_action(rule_header rule)
{
    int action = PASS;
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
    return action;
}

int get_action(std::string protocol, std::string src_ip, std::string src_port, std::string dst_ip, std::string dst_port, std::vector<rule_header> &rules, int mode)
{
    int action = PASS;
    for (auto &rule : rules)
    {
        if (match_packet(protocol, src_ip, src_port, dst_ip, dst_port, rule))
        {
            if (!rule.option)
            {
                action = rule_action_to_app_action(rule);
                break;
            }
            else
            {
                if (get_cpu_usage() >= rule.cpu_usage)
                {
                    action = rule_action_to_app_action(rule);
                    break;
                }
                else if (rule.match_packet_count)
                {
                    action = rule_action_to_app_action(rule);
                    break;
                }
                else if (rule.count > 0 && rule.time > 0)
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
                            action = rule_action_to_app_action(rule);
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
