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

int get_action(std::string protocol, std::string src_ip, std::string src_port, std::string dst_ip, std::string dst_port, std::vector<rule_header> &rules)
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
                double cpu = get_cpu_last_second();
                if (cpu >= rule.cpu_usage)
                {
                    action = rule_action_to_app_action(rule);
                    break;
                }
                else if (rule.match_packet_count)
                {
                    action = rule_action_to_app_action(rule);
                    auto curr_time = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(curr_time - rule.start_time_out).count();
                    if (duration >= rule.timeout * 1000000)
                    {
                        rule.packet_count = 0;
                        rule.match_packet_count = false;
                    }
                    break;
                }
                else if (rule.count > 0 && rule.second > 0)
                {
                    if (rule.packet_count == 0)
                    {
                        rule.start_time = std::chrono::high_resolution_clock::now();
                    }
                    rule.packet_count++;
                    if (rule.packet_count >= rule.count)
                    {
                        auto curr_time = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(curr_time - rule.start_time).count();
                        if (duration <= rule.second * 1000000)
                        {
                            rule.match_packet_count = true;
                            rule.start_time_out = std::chrono::high_resolution_clock::now();
                            action = rule_action_to_app_action(rule);
                            break;
                        }
                        else
                        {
                            rule.packet_count = 0;
                        }
                    }
                }
            }
        }
    }
    return action;
}
